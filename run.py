from app import create_app
import os

app = create_app(os.getenv('FLASK_ENV', 'development'))

if __name__ == '__main__':
    # Run the application
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=app.config['DEBUG']
    )

from apscheduler.schedulers.background import BackgroundScheduler
from app.ml.feedback_learning import FeedbackLearner

def scheduled_retraining():
    """Automatically retrain models weekly"""
    with app.app_context():
        learner = FeedbackLearner()
        learner.full_feedback_learning_cycle(days_back=7)

scheduler = BackgroundScheduler()
scheduler.add_job(
    func=scheduled_retraining,
    trigger="cron",
    day_of_week='sun',  # Every Sunday
    hour=2,             # At 2 AM
    minute=0
)
scheduler.start()
