from flask import Blueprint, redirect, url_for
from flask_login import login_required

bp = Blueprint('admin', __name__, url_prefix='/admin')


# ---------------------------------------------------------
# This used to be a second, independent "retrain" view that duplicated
# dashboard.retrain_models (app/routes/dashboard.py) but without reading
# the days_back form field and without passing total_alerts/closed_threats/
# false_positives to admin_retrain.html — so its own GET path raised
# UndefinedError (500) the moment it rendered, and the admin_retrain.html
# form used to POST here even when reached via the properly-linked
# dashboard.retrain_models page. Now it just forwards to the real route.
# ---------------------------------------------------------
@bp.route('/retrain', methods=['GET', 'POST'])
@login_required
def retrain():
    return redirect(url_for('dashboard.retrain_models'))
