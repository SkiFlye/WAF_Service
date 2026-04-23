import asyncio
import threading
from waitress import serve
from app.routes import app
from proxy.server import waf_proxy


def run_flask():
    serve(app, host='0.0.0.0', port=5000)


def run_proxy():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(waf_proxy.start())
    loop.run_forever()


if __name__ == '__main__':
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    run_proxy()