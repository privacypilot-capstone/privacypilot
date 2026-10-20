# Analytics service for LearnIndia
# PLANTED VIOLATIONS: V3 (name + email sent to Mixpanel)

import mixpanel

MIXPANEL_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
mp = mixpanel.Mixpanel(MIXPANEL_TOKEN)

def track_course_progress(student):
    """
    PLANTED V3 — Sends student name and email to Mixpanel.
    Analytics use not disclosed in privacy policy.
    """
    mp.track(student.email, 'course_progress', {
        'name':     student.full_name,
        'phone':    student.phone_number,
        'course':   student.course_enrolled,
        'progress': student.progress,
        'location': f"{student.latitude},{student.longitude}",
    })


def track_attendance(student_id, latitude, longitude):
    """
    Tracks student attendance using GPS coordinates.
    Location data sent to analytics.
    """
    mp.track(student_id, 'attendance_marked', {
        'latitude':  latitude,
        'longitude': longitude,
    })
