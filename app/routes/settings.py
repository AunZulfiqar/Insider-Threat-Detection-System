from flask import Blueprint, redirect, url_for
from flask_login import login_required

bp = Blueprint('settings', __name__, url_prefix='/settings')


# ---------------------------------------------------------
# This blueprint used to keep its own copy of detection settings
# in the SystemSettings DB table. That copy was never read by the
# detection engine (app/utils/detection_engine.py and
# app/models/ml_model.py both read app/config/settings.json), so
# changes made here had no effect on real detection behavior.
#
# dashboard.settings (app/routes/dashboard.py) is the settings page
# that's actually wired to the detection engine and linked in the
# nav bar. This route now just forwards there so old links/bookmarks
# to /settings/ still work.
# ---------------------------------------------------------
@bp.route('/', methods=['GET', 'POST'])
@login_required
def settings():
    return redirect(url_for('dashboard.settings'))
