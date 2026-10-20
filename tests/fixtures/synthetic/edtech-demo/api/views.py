# API views for LearnIndia platform

from models.student import Student
from services.analytics import track_course_progress

def register_student(request):
    data = request.POST
    student = Student.objects.create(
        full_name     = data['full_name'],
        email         = data['email'],
        phone_number  = data['phone_number'],
        date_of_birth = data['date_of_birth'],
        latitude      = data['latitude'],
        longitude     = data['longitude'],
        address       = data['address'],
        course_enrolled = data['course'],
    )
    track_course_progress(student)
    return {"status": "registered", "id": student.id}


def get_student_profile(request, student_id):
    student = Student.objects.get(id=student_id)
    return {
        "name":          student.full_name,
        "date_of_birth": str(student.date_of_birth),
        "latitude":      str(student.latitude),
        "longitude":     str(student.longitude),
        "course":        student.course_enrolled,
        "progress":      student.progress,
    }
