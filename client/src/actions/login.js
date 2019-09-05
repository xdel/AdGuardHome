import { createAction } from 'redux-actions';

import Api from '../api/Api';
import { addErrorToast } from './index';

const apiClient = new Api();

export const processLoginRequest = createAction('PROCESS_LOGIN_REQUEST');
export const processLoginFailure = createAction('PROCESS_LOGIN_FAILURE');
export const processLoginSuccess = createAction('PROCESS_LOGIN_SUCCESS');

export const processLogin = values => async (dispatch) => {
    dispatch(processLoginRequest());
    try {
        await apiClient.login(values);
        window.location.replace(window.location.origin);
        dispatch(processLoginSuccess());
    } catch (error) {
        dispatch(addErrorToast({ error }));
        dispatch(processLoginFailure());
    }
};
