# MicroCNI - A Minimal Container Network Interface Plugin

1. Place the `microcni.conf` file in the `/etc/cni/net.d/` directory.
  a. Make sure the "podcidr" is different for each node.

2. Choose either the Go or the Bash implementation of the MicroCNI plugin.
  a. If you choose the Go implementation, first build the plugin with `make`.
  b. Put the final binary in the `/opt/cni/bin/` directory.
  c. Make sure the binary is executable.
  d. Make sure the binary is named `microcni` and matches the "type" in the `microcni.conf` file.
  e. Mkae sure to have `jq` installed on the nodes.

3. Run the `init.sh` on each node with the correct IPs and IP ranges.
