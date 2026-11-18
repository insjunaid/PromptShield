"""Names shared by the gateway and the stdio bridge, kept apart so the bridge starts fast.

The bridge is what an AI app launches, and apps give up on an MCP server that's slow to answer;
importing the gateway itself (the shield, its models, Starlette) would cost seconds.
"""

SERVER_NAME = "promptshield-gateway"
TASK_HEADER = "x-promptshield-task"
