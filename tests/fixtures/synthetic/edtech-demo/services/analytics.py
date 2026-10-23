"""Analytics service for LearnIndia."""

import mixpanel

MIXPANEL_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
mp = mixpanel.Mixpanel(MIXPANEL_TOKEN)


# Benchmark negative control:
# Mentioning personal data or an analytics provider in documentation
# does not itself establish that data is transmitted.


def track_course_progress(student):
    """Track course progress for the analytics service."""
    mp.track(
        student.email,
        "course_progress",
        {
            "name": student.full_name,
            "phone": student.phone_number,
            "course": student.course_enrolled,
            "progress": student.progress,
            "location": f"{student.latitude},{student.longitude}",
        },
    )


def track_attendance(student_id, latitude, longitude):
    """Track attendance using GPS coordinates."""
    mp.track(
        student_id,
        "attendance_marked",
        {
            "latitude": latitude,
            "longitude": longitude,
        },
    )
