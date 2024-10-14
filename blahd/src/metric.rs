use std::time::Duration;

use axum::Router;
use futures_util::future::BoxFuture;
use metrics::Recorder;
use metrics_exporter_prometheus::PrometheusBuilder;
use tokio::time::{interval, MissedTickBehavior};

use crate::config::MetricConfig;

type DynRecorder = Box<dyn Recorder + Send + Sync>;
type UpkeeperTask = BoxFuture<'static, ()>;

pub fn metrics_router(config: &MetricConfig) -> (Router, DynRecorder, UpkeeperTask) {
    let MetricConfig::Prometheus(config) = config;

    let recorder = PrometheusBuilder::new()
        .set_bucket_duration(Duration::from_secs(
            config.bucket_duration_secs.get().into(),
        ))
        .expect("not zero")
        .build_recorder();

    let handle_render = recorder.handle();
    let get_metrics = || async move { handle_render.render() };

    let upkeeper = Box::pin({
        let handle_upkeep = recorder.handle();
        let upkeep_period = Duration::from_secs(config.upkeep_period_secs.get().into());
        async move {
            let mut interval = interval(upkeep_period);
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                handle_upkeep.run_upkeep();
            }
        }
    }) as _;

    let router = Router::new().route("/metrics", axum::routing::get(get_metrics));
    (router, Box::new(recorder) as _, upkeeper)
}
