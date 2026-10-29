import sys

def main():
    """CLI launcher for WireTapper."""
    args = sys.argv[1:]
    if args and args[0] in ['-start', '--start', 'start', 'run']:
        print("Starting WireTapper Signal Intelligence Platform on http://0.0.0.0:8080 ...")
    else:
        print("Starting WireTapper Signal Intelligence Platform on http://0.0.0.0:8080 ...")

    from app import app
    app.run(host="0.0.0.0", port=8080, debug=False)

if __name__ == '__main__':
    main()
