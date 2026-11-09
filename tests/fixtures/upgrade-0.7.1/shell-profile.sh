# unifi-fabric-mcp
export UNIFI_API_KEY="your-api-key-here"
export UNIFI_READ_ONLY=1   # read-only first run
export UNIFI_TOOL_FAMILIES="network,protect"

docker run --rm -i -e UNIFI_API_KEY -e UNIFI_DRY_RUN=1 -e UNIFI_ENABLE_CONNECTOR_WRITE=0 ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.0
