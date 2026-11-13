export default function (pi) {
  pi.registerTool({
    name: 'ping',
    description: 'Reply pong. Confirms the MPA plugin worker is running.',
    parameters: { type: 'object', properties: {} },
    async execute() {
      return 'pong'
    },
  })
  pi.on('session_start', (_event, ctx) => {
    ctx.ui.notify('hello-mpa loaded', 'info')
  })
  pi.on('tool_call', (event) => {
    const command = String((event.input && event.input.command) || '')
    if (event.toolName === 'agent_bash' && command.includes('rm -rf /')) {
      return { block: true, reason: 'hello-mpa blocked a destructive bash command' }
    }
  })
}
