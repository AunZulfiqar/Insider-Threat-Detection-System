import os

from apscheduler.schedulers.background import BackgroundScheduler

from app import create_app
from app.ml.feedback_learning import FeedbackLearner

app = create_app(os.getenv('FLASK_ENV', 'development'))


def scheduled_retraining():
    """Automatically retrain models weekly"""
    with app.app_context():
        learner = FeedbackLearner()
        learner.full_feedback_learning_cycle(days_back=7)


if __name__ == '__main__':
    # FIX: this used to sit after the blocking app.run() call below, so it
    # never actually ran — the weekly auto-retrain job was dead code.
    #
    # Guarded by WERKZEUG_RUN_MAIN so Werkzeug's debug-mode reloader (which
    # re-execs this whole script in a child process) doesn't start a second,
    # duplicate scheduler alongside the reloader's parent watcher process.
    if not app.config['DEBUG'] or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        scheduler = BackgroundScheduler()
        scheduler.add_job(
            func=scheduled_retraining,
            trigger="cron",
            day_of_week='sun',  # Every Sunday
            hour=2,             # At 2 AM
            minute=0
        )
        scheduler.start()

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=app.config['DEBUG']
    )
