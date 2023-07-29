Unifi prom SD
===

Expose Ubiquity unify devices for probing with the prometheus blackbox exporter
using http service discovery.

## Example config

```json
{
    "unifi_url": "https://controller",
    "site": "default",
    "username": "user",
    "password": "password",
    "insecure_https": true,
    "blackbox_url": "http://blackbox",
    "listen_port": 8080
}