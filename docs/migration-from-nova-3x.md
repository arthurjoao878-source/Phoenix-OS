# Migration from Nova 3.x

Nova 3.x remains outside the Kernel. Migration is incremental:

1. Wrap each Nova input channel as a `Request` producer.
2. Wrap tools, memory, AI, and persistence as handlers or services behind handlers.
3. Observe Kernel lifecycle through Event Bus subscriptions.
4. Keep legacy SQLite event persistence in an adapter subscribed to selected events.
5. Never import Nova UI, database, AI client, or Windows automation into `phoenix_os.kernel`
   or `phoenix_os.events`.

The existing Nova event names may be translated by an adapter. They are not made Kernel
contracts automatically.
