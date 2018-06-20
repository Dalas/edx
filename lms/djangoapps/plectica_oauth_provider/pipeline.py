import string  # pylint: disable-msg=deprecated-module
import json
import logging

from cms.djangoapps.course_creators.models import CourseCreator
from django.http import HttpResponseBadRequest, HttpResponse
from django.contrib.auth.models import User
from social_django.models import UserSocialAuth

from social_core.pipeline import partial

from student.views import create_account_with_params, reactivation_email_for_user
from student.models import UserProfile, CourseAccessRole, CourseEnrollment
from student.roles import (
    CourseInstructorRole, CourseStaffRole, GlobalStaff, OrgStaffRole,
    UserBasedRole, CourseCreatorRole, CourseBetaTesterRole, OrgInstructorRole,
    LibraryUserRole, OrgLibraryUserRole
)
from third_party_auth.pipeline import (
    make_random_password, AuthEntryError, redirect_to_custom_form, AUTH_ENTRY_LOGIN, AUTH_ENTRY_REGISTER,
    AUTH_ENTRY_ACCOUNT_SETTINGS, AUTH_ENTRY_LOGIN_API, AUTH_ENTRY_REGISTER_API, AUTH_ENTRY_CUSTOM
)
from opaque_keys.edx.locations import SlashSeparatedCourseKey


import logging
logger = logging.getLogger(__name__)


REQUIRED_ENTRIES = [
    AUTH_ENTRY_LOGIN, AUTH_ENTRY_REGISTER, AUTH_ENTRY_LOGIN_API, AUTH_ENTRY_REGISTER_API
]


@partial.partial
def ensure_user_information(
    strategy, auth_entry, backend=None, user=None, social=None,
    allow_inactive_user=False, *args, **kwargs):
    """
    Ensure that we have the necessary information about a user (either an
    existing account or registration data) to proceed with the pipeline.
    """

    response = {}
    data = kwargs['response']
    display_name = data.get('display_name').split(" ")
    data['first_name'] = display_name[0]
    data['last_name'] = display_name[1] if len(display_name) >= 2 else ''
    data['name'] = data.get('display_name')
    data['username'] = data.get('display_name')

    def dispatch_to_register():
        """Force user creation on login or register"""

        request = strategy.request
        data['terms_of_service'] = "True"
        data['honor_code'] = 'True'
        data['password'] = make_random_password()

        data['provider'] = backend.name

        if request.session.get('ExternalAuthMap'):
            del request.session['ExternalAuthMap']

        try:
            user = UserSocialAuth.objects.get(uid=data['user_id'])
            user = user.user
        except UserSocialAuth.DoesNotExist:
            # TODO: if you need some additional info about user -> change this
            create_account_with_params(request, data)
            user = request.user
            user.first_name = data['first_name']
            user.last_name = data['last_name']
            user.is_active = True
            user.save()

            try:
                course_id = SlashSeparatedCourseKey.from_deprecated_string(data['course_id'])
                CourseEnrollment.enroll(user, course_id)
            except Exception as e:
                logger.error('Handle error while enrolling user on course {}'.format(e))

            CourseCreator.objects.get_or_create(
                user=user,
                state=CourseCreator.UNREQUESTED
            )
        return {'user': user}

    if not user:
        if auth_entry in [AUTH_ENTRY_LOGIN_API, AUTH_ENTRY_REGISTER_API]:
            return HttpResponseBadRequest()
        elif auth_entry in [AUTH_ENTRY_LOGIN, AUTH_ENTRY_REGISTER]:
            return dispatch_to_register()
        elif auth_entry == AUTH_ENTRY_ACCOUNT_SETTINGS:
            raise AuthEntryError(backend, 'auth_entry is wrong. Settings requires a user.')
        elif auth_entry in AUTH_ENTRY_CUSTOM:
            return redirect_to_custom_form(strategy.request, auth_entry, kwargs)
        else:
            raise AuthEntryError(backend, 'auth_entry invalid')
    else:
        if user.id != 1:
            user.email = data['email']
            user.username = data['username']
            user.first_name = data['first_name']
            user.last_name = data['last_name']
            user.save()
            CourseCreator.objects.get_or_create(
                user=user,
                state=CourseCreator.UNREQUESTED
            )
        try:
            user_profile = UserProfile.objects.get(user=user)
        except User.DoesNotExist:
            user_profile = None
        except User.MultipleObjectsReturned:
            user_profile = UserProfile.objects.filter(user=user)[0]

        if user_profile:
            user_profile.name = user.get_full_name()
            user_profile.save()

    user = user or response.get('user')
    if user and not user.is_active:
        if allow_inactive_user:
            pass
        elif social is not None:
            reactivation_email_for_user(user)
            raise AuthEntryError(backend, user.email)

    return {'user': user}
