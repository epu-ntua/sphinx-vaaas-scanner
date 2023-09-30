def init():
    global assets
    assets = {
        "app_scheduler": None,
        "socket_io": None,
        "db_manager": None,
    }


def set_asset(key: str, value):
    assets[key] = value


def get_asset(key: str):
    return assets.get(key)
