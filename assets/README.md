# Vendored assets

`echarts.min.js` — Apache ECharts 6.1.0, Apache-2.0 licensed
(https://echarts.apache.org/). Vendored rather than loaded from a CDN so the
admin interface works on a host with no internet access, and so the admin
surface has no third-party runtime dependency. It is compiled into the binary
with `include_str!` and served from `/_management/echarts.min.js`.

To update: download the new `echarts.min.js` from the ECharts release and
replace this file.
