from datetime import datetime, timedelta
from time import sleep
from unittest.mock import patch

from pgtracer.ebpf.guc import GUCTracerEventHandler


def test_setting_one_guc(guctracer, connection):
    """
    Test to set a GUC in a running backend.
    """
    guc_has_been_set = False
    original_method = GUCTracerEventHandler.handle_GUCResponse

    def observe_guc_response(event_handler, collector, event):
        nonlocal guc_has_been_set
        guc_has_been_set = True
        return original_method(event_handler, collector, event)

    with patch(
        f"pgtracer.ebpf.guc.GUCTracerEventHandler.handle_GUCResponse",
        observe_guc_response,
    ):
        # Set work_mem to 64kB
        guctracer.set_guc("work_mem", 64)
        start = datetime.now()
        while not guc_has_been_set and (datetime.now() - start) < timedelta(seconds=20):
            # Generate some activity to trigger the probe
            with connection.execute("SELECT 1") as cur:
                pass
            sleep(0.1)
        with connection.execute("show work_mem") as cur:
            result = cur.fetchall()
            val = result[0][0]
            # Depending on the version, it can come back as str or bytes
            if isinstance(val, bytes):
                val = val.decode("utf8")
            assert val == "64kB"
