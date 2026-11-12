// Package telemetry sets up OpenTelemetry traces, metrics and logs from the standard OTEL_* env vars,
// and the logger that writes JSON to stdout and, when configured, OTLP log records.
package telemetry

import (
	"context"
	"io"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const scope = "github.com/RapidataAI/pgauth"

// Setup exports spans, metrics and logs only when an OTLP endpoint is set; OTEL_LOGS_EXPORTER=none
// and friends switch one signal off. The returned provider is nil when nothing is exported.
func Setup(ctx context.Context) (shutdown func(), logs otellog.LoggerProvider, err error) {
	if !configured() {
		return func() {}, nil, nil
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(attribute.String("service.name", "pgauth")))
	if err != nil {
		return nil, nil, err
	}
	if res, err = resource.Merge(res, resource.Environment()); err != nil {
		return nil, nil, err
	}
	spans, err := autoexport.NewSpanExporter(ctx)
	if err != nil {
		return nil, nil, err
	}
	metrics, err := autoexport.NewMetricReader(ctx)
	if err != nil {
		return nil, nil, err
	}
	logExp, err := autoexport.NewLogExporter(ctx)
	if err != nil {
		return nil, nil, err
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(spans), sdktrace.WithResource(res))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(metrics), sdkmetric.WithResource(res))
	lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)), sdklog.WithResource(res))
	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = lp.Shutdown(ctx)
		_ = tp.Shutdown(ctx)
		_ = mp.Shutdown(ctx)
	}, lp, nil
}

func configured() bool {
	for _, v := range []string{"", "_TRACES", "_METRICS", "_LOGS"} {
		if os.Getenv("OTEL_EXPORTER_OTLP"+v+"_ENDPOINT") != "" {
			return true
		}
	}
	return false
}

// Logger writes JSON lines to w and, when logs is set, the same records to OpenTelemetry; a record
// logged with a span's context carries its trace and span ids.
func Logger(w io.Writer, logs otellog.LoggerProvider) *slog.Logger {
	h := slog.Handler(slog.NewJSONHandler(w, nil))
	if logs != nil {
		h = slog.NewMultiHandler(h, otelslog.NewHandler(scope, otelslog.WithLoggerProvider(logs)))
	}
	return slog.New(h)
}
