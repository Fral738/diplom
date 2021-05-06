from app import app
from app import logger

if __name__ == '__main__':
    logger.info("server started")
    app.run(host="0.0.0.0", debug=True)
