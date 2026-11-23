#!/bin/bash
# FUSE ftrace control script

# Setup ftrace directories
if [[ -e /sys/kernel/tracing/trace ]]; then
    TR=/sys/kernel/tracing/
else
    TR=/sys/kernel/debug/tracing/
fi

# Helper functions
clear_trace() {
    echo > $TR/trace
}

enable_tracing() {
    if ! echo 1 > $TR/tracing_on; then
        echo "Error: Failed to enable tracing"
        exit 1
    fi
    echo "Tracing enabled"
}

disable_tracing() {
    if ! echo 0 > $TR/tracing_on; then
        echo "Error: Failed to disable tracing"
        exit 1
    fi
    echo "Tracing disabled"
}

reset_tracer() {
    echo nop > $TR/current_tracer
    echo > $TR/set_ftrace_filter
    echo > $TR/set_event
}

undo_setup_function() {
    disable_tracing
    # Remove FUSE function filters
    echo '!fuse:*' > $TR/set_ftrace_filter 2>/dev/null
    echo '!fuse_*' >> $TR/set_ftrace_filter 2>/dev/null
    echo nop > $TR/current_tracer
    echo "Function tracing configuration removed"
}

undo_setup_request() {
    disable_tracing
    # Remove all FUSE request events
    echo '!fuse:fuse_request_enqueue' > $TR/set_event 2>/dev/null
    echo '!fuse:fuse_request_bg_enqueue' >> $TR/set_event 2>/dev/null
    echo '!fuse:fuse_request_send' >> $TR/set_event 2>/dev/null
    echo '!fuse:fuse_request_end' >> $TR/set_event 2>/dev/null
    echo "Request tracing configuration removed"
}

setup_function_trace() {
    disable_tracing
    clear_trace
    reset_tracer
    
    # Set function tracer
    if ! grep -q "function" $TR/available_tracers; then
        echo "Error: function tracer not available"
        exit 1
    fi
    
    echo function > $TR/current_tracer
    echo "fuse:*" > $TR/set_ftrace_filter 2>/dev/null
    echo "fuse_*" >> $TR/set_ftrace_filter 2>/dev/null

    enable_tracing

    echo "Function tracing configured and enabled"
}

setup_request_trace() {
    disable_tracing
    clear_trace
    reset_tracer

    # Verify FUSE events are available
    if ! grep -q "fuse:fuse_request" $TR/available_events; then
        echo "Error: FUSE tracepoints not available"
        exit 1
    fi

    # Enable all relevant FUSE request events
    if ! echo "fuse:fuse_request_enqueue" > $TR/set_event 2>/dev/null || \
       ! echo "fuse:fuse_request_bg_enqueue" >> $TR/set_event 2>/dev/null || \
       ! echo "fuse:fuse_request_send" >> $TR/set_event 2>/dev/null || \
       ! echo "fuse:fuse_request_end" >> $TR/set_event 2>/dev/null; then
        echo "Error: Failed to enable FUSE request events"
        exit 1
    fi

    # Verify events were actually enabled
    if ! grep -q "fuse:fuse_request" $TR/set_event; then
        echo "Error: Failed to verify FUSE events are enabled"
        exit 1
    fi

    enable_tracing

    echo "Request tracing configured and enabled"
    echo "Active events:"
    cat $TR/set_event
    echo "Tracing status: $(cat $TR/tracing_on)"
}

usage() {
    echo "Usage: $0 [command]"
    echo "Commands:"
    echo "  start           - Start tracing"
    echo "  stop            - Stop tracing"
    echo "  show            - Show current trace buffer"
    echo "  clear           - Clear trace buffer"
    echo "  setup-func      - Setup function tracing"
    echo "  setup-req       - Setup request tracing"
    echo "  undo-setup-func - Remove function tracing configuration"
    echo "  undo-setup-req  - Remove request tracing configuration"
    echo "  reset           - Reset all tracing settings"
    echo "  status          - Show current trace configuration"
    exit 1
}

show_status() {
    echo "=== Trace Configuration ==="
    echo "Current Tracer: $(cat $TR/current_tracer)"
    echo "Tracing Status: $(cat $TR/tracing_on)"
    echo
    echo "Active Function Filters:"
    cat $TR/set_ftrace_filter
    echo
    echo "Active Events:"
    cat $TR/set_event
}

case "$1" in
    "start")
        enable_tracing
        echo "Tracing started"
        ;;
    "stop")
        disable_tracing
        echo "Tracing stopped"
        ;;
    "show")
        echo "=== FUSE Trace Results ==="
        cat $TR/trace
        ;;
    "clear")
        clear_trace
        echo "Trace buffer cleared"
        ;;
    "setup-func")
        setup_function_trace
        ;;
    "setup-req")
        setup_request_trace
        ;;
    "undo-setup-func")
        undo_setup_function
        ;;
    "undo-setup-req")
        undo_setup_request
        ;;
    "reset")
        disable_tracing
        reset_tracer
        clear_trace
        echo "All tracing settings reset"
        ;;
    "status")
        show_status
        ;;
    *)
        usage
        ;;
esac

