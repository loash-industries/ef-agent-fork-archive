//! Live model context windows: keeps the `context_window` of every provider
//! that opts into `live_context_window` in step with the provider's own
//! `/models` listing.
//!
//! Setup writes `context_window` once, from whatever model was configured at
//! the time. That number then goes stale the moment the operator points the
//! alias at a different model — including through the in-process
//! `model_switch` tool, which never touches the file. This refresher closes
//! that gap: it re-reads the advertised window hourly and updates the
//! *in-memory* config, so every existing resolver
//! ([`Config::effective_model_context_window`], and through it the default
//! context-trimming budget) follows the model actually in use.
//!
//! It deliberately does NOT save the config. The fetched window is derived
//! data with a live source; persisting it hourly would churn the file and
//! bake in a snapshot that is wrong again as soon as the model changes.

use parking_lot::RwLock;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::Duration;
use zeroclaw_config::schema::{Config, ModelProviderConfig};

/// How often the background task re-reads advertised windows. Matches the
/// pricing refresher: model metadata changes on the order of releases, not
/// minutes.
const REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);

static CONFIG_HANDLE: LazyLock<RwLock<Option<Arc<RwLock<Config>>>>> =
    LazyLock::new(|| RwLock::new(None));

/// Guards against spawning more than one refresher when both the channels
/// orchestrator and the gateway start in the same process.
static REFRESHER_STARTED: OnceLock<()> = OnceLock::new();

/// True when at least one model provider opts into `live_context_window`.
fn any_live_context_window(config: &Config) -> bool {
    config
        .providers
        .models
        .iter_entries()
        .any(|(_, _, base)| base.live_context_window)
}

/// One provider alias whose window should be refreshed. Carries a clone of
/// the provider config so the fetch runs without holding the config lock.
struct WantedWindow {
    provider_type: &'static str,
    alias: String,
    /// The model the window is fetched *for*. Re-checked before the result is
    /// applied, so a `model_switch` that lands mid-fetch is not overwritten
    /// with the previous model's window.
    model: String,
    provider_config: ModelProviderConfig,
}

/// Collect every opted-in alias that names a model. An alias without a model
/// has nothing to look up in the listing, so it is skipped rather than
/// fetched for the empty string.
fn wanted_windows(config: &Config) -> Vec<WantedWindow> {
    config
        .providers
        .models
        .iter_entries()
        .filter(|(_, _, base)| base.live_context_window)
        .filter_map(|(ty, alias, base)| {
            let model = base
                .model
                .as_deref()
                .map(str::trim)
                .filter(|m| !m.is_empty())?;
            Some(WantedWindow {
                provider_type: ty,
                alias: alias.to_string(),
                model: model.to_string(),
                provider_config: base.clone(),
            })
        })
        .collect()
}

/// Apply fetched windows to `config`. Pure with respect to the network --
/// the fetch happens in [`refresh_once`], so the decision logic here is unit
/// testable. Returns the number of entries actually changed.
///
/// A provider whose fetch failed (network, unsupported family, model absent
/// from the listing) keeps its previous value rather than having it cleared:
/// a stale window is strictly better than none, which would collapse budget
/// arithmetic onto the conservative fallback.
fn apply_fetched(config: &mut Config, fetched: Vec<(WantedWindow, Option<usize>)>) -> usize {
    let mut changed = 0;
    for (want, window) in fetched {
        let Some(window) = window.filter(|&w| w > 0) else {
            ::zeroclaw_log::record!(
                DEBUG,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({
                        "provider": format!("{}.{}", want.provider_type, want.alias),
                        "model": want.model,
                    })),
                "live context window: no window advertised; keeping the previous value"
            );
            continue;
        };
        let Some((_, _, base)) = config
            .providers
            .models
            .iter_entries_mut()
            .find(|(ty, alias, _)| *ty == want.provider_type && *alias == want.alias)
        else {
            continue; // alias removed while the un-locked fetch was in flight
        };
        // The alias may have been re-pointed mid-fetch; this window describes
        // the old model, so drop it and let the next cycle fetch the new one.
        if base.model.as_deref().map(str::trim) != Some(want.model.as_str()) {
            continue;
        }
        if base.context_window == Some(window) {
            continue;
        }
        ::zeroclaw_log::record!(
            INFO,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_attrs(
                ::serde_json::json!({
                    "provider": format!("{}.{}", want.provider_type, want.alias),
                    "model": want.model,
                    "previous": base.context_window,
                    "context_window": window,
                })
            ),
            "live context window: updated from the provider listing"
        );
        base.context_window = Some(window);
        changed += 1;
    }
    changed
}

/// Fetch every wanted window concurrently, then apply the results under one
/// short write lock. The lock is never held across an `.await`.
async fn refresh_once(handle: &Arc<RwLock<Config>>, wanted: Vec<WantedWindow>) {
    let fetched = futures_util::future::join_all(wanted.into_iter().map(|want| async move {
        let window = crate::fetch_context_window(want.provider_type, &want.provider_config).await;
        (want, window)
    }))
    .await;

    apply_fetched(&mut handle.write(), fetched);
}

/// Spawn the background context-window refresher, once per process.
///
/// No-op when no provider currently sets `live_context_window = true`: zero
/// network, zero task, and the configured windows stand untouched. As in the
/// pricing refresher, this pre-check runs *before* the once-per-process
/// guard is claimed, so an `/admin/reload` that newly enables a provider can
/// still start the refresher.
///
/// `CONFIG_HANDLE` is re-bound on every call and re-resolved each cycle, so a
/// daemon reload (which re-instantiates the config `Arc`) re-points the
/// refresher at the current config without a restart.
pub fn spawn_refresher(config: Arc<RwLock<Config>>) {
    // Re-bind before the enabled pre-check so even a "nothing enabled yet"
    // call leaves the freshest handle for a refresher started later.
    *CONFIG_HANDLE.write() = Some(Arc::clone(&config));
    if !any_live_context_window(&config.read()) {
        return;
    }
    if REFRESHER_STARTED.set(()).is_err() {
        return; // already running
    }

    ::zeroclaw_spawn::spawn!(async {
        loop {
            // Re-resolve the handle (re-bound across daemon reloads), then
            // read the wanted set under the lock and fetch without holding
            // it. The handle is bound above before this task can exist, and
            // never unbound, so the `expect` cannot fire.
            let handle = CONFIG_HANDLE
                .read()
                .clone()
                .expect("config handle is bound before the refresher is spawned");
            let wanted = wanted_windows(&handle.read());
            if !wanted.is_empty() {
                refresh_once(&handle, wanted).await;
            }
            tokio::time::sleep(REFRESH_INTERVAL).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_config::schema::OpenRouterModelProviderConfig;

    /// Build a config with one OpenRouter alias.
    fn config_with(
        alias: &str,
        model: Option<&str>,
        live: bool,
        context_window: Option<usize>,
    ) -> Config {
        let mut config = Config::default();
        config.providers.models.openrouter.insert(
            alias.to_string(),
            OpenRouterModelProviderConfig {
                base: ModelProviderConfig {
                    model: model.map(ToString::to_string),
                    live_context_window: live,
                    context_window,
                    ..Default::default()
                },
            },
        );
        config
    }

    fn want(alias: &str, model: &str) -> WantedWindow {
        WantedWindow {
            provider_type: "openrouter",
            alias: alias.to_string(),
            model: model.to_string(),
            provider_config: ModelProviderConfig::default(),
        }
    }

    #[test]
    fn refresher_is_a_no_op_without_an_opted_in_provider() {
        let config = config_with("or", Some("z-ai/glm-5.3-flash"), false, Some(32_000));
        assert!(!any_live_context_window(&config));
        assert!(
            wanted_windows(&config).is_empty(),
            "a provider that never opted in must not be fetched for"
        );
    }

    #[test]
    fn opted_in_provider_without_a_model_is_skipped() {
        // An empty model has nothing to match in the listing; fetching for it
        // would look up the empty string.
        let config = config_with("or", Some("   "), true, None);
        assert!(any_live_context_window(&config));
        assert!(wanted_windows(&config).is_empty());
    }

    #[test]
    fn opted_in_provider_with_a_model_is_wanted() {
        let config = config_with("or", Some("z-ai/glm-5.3-flash"), true, None);
        let wanted = wanted_windows(&config);
        assert_eq!(wanted.len(), 1);
        assert_eq!(wanted[0].provider_type, "openrouter");
        assert_eq!(wanted[0].alias, "or");
        assert_eq!(wanted[0].model, "z-ai/glm-5.3-flash");
    }

    #[test]
    fn fetched_window_replaces_the_stale_configured_one() {
        let mut config = config_with("or", Some("z-ai/glm-5.3-flash"), true, Some(32_000));
        let changed = apply_fetched(
            &mut config,
            vec![(want("or", "z-ai/glm-5.3-flash"), Some(1_310_720))],
        );
        assert_eq!(changed, 1);
        assert_eq!(
            config.effective_model_context_window("zero"),
            32_000,
            "no agent is bound to this alias, so the fallback still applies"
        );
        let (_, _, base) = config.providers.models.iter_entries().next().unwrap();
        assert_eq!(base.context_window, Some(1_310_720));
    }

    #[test]
    fn failed_fetch_keeps_the_previous_window_rather_than_clearing_it() {
        let mut config = config_with("or", Some("z-ai/glm-5.3-flash"), true, Some(1_310_720));
        let changed = apply_fetched(&mut config, vec![(want("or", "z-ai/glm-5.3-flash"), None)]);
        assert_eq!(changed, 0);
        let (_, _, base) = config.providers.models.iter_entries().next().unwrap();
        assert_eq!(
            base.context_window,
            Some(1_310_720),
            "a stale window beats none: clearing it collapses budget arithmetic onto the fallback"
        );
    }

    #[test]
    fn zero_window_is_rejected_as_no_answer() {
        let mut config = config_with("or", Some("z-ai/glm-5.3-flash"), true, Some(1_310_720));
        apply_fetched(&mut config, vec![(want("or", "z-ai/glm-5.3-flash"), Some(0))]);
        let (_, _, base) = config.providers.models.iter_entries().next().unwrap();
        assert_eq!(base.context_window, Some(1_310_720));
    }

    #[test]
    fn window_for_a_superseded_model_is_discarded() {
        // `model_switch` re-pointed the alias while the fetch was in flight;
        // applying the old model's window would be actively wrong.
        let mut config = config_with("or", Some("anthropic/claude-sonnet-4-6"), true, Some(200_000));
        let changed = apply_fetched(
            &mut config,
            vec![(want("or", "z-ai/glm-5.3-flash"), Some(1_310_720))],
        );
        assert_eq!(changed, 0);
        let (_, _, base) = config.providers.models.iter_entries().next().unwrap();
        assert_eq!(base.context_window, Some(200_000));
    }

    #[test]
    fn window_for_a_removed_alias_is_dropped_without_panicking() {
        let mut config = Config::default();
        let changed = apply_fetched(
            &mut config,
            vec![(want("gone", "z-ai/glm-5.3-flash"), Some(1_310_720))],
        );
        assert_eq!(changed, 0);
    }

    #[test]
    fn unchanged_window_is_not_rewritten() {
        let mut config = config_with("or", Some("z-ai/glm-5.3-flash"), true, Some(1_310_720));
        let changed = apply_fetched(
            &mut config,
            vec![(want("or", "z-ai/glm-5.3-flash"), Some(1_310_720))],
        );
        assert_eq!(changed, 0);
    }
}
