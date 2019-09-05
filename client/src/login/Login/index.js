import React, { Component } from 'react';
import { connect } from 'react-redux';
import PropTypes from 'prop-types';

import * as actionCreators from '../../actions/login';
import logo from '../../components/ui/svg/logo.svg';
import Toasts from '../../components/Toasts';
import Form from './Form';

import './Login.css';
import '../../components/ui/Tabler.css';

class Login extends Component {
    handleSubmit = ({ username: name, password }) => {
        this.props.processLogin({ name, password });
    };

    render() {
        const { processingLogin } = this.props.login;

        return (
            <div className="page-single pt-6">
                <div className="container">
                    <div className="row">
                        <div className="col col-login mx-auto">
                            <div className="text-center mb-6">
                                <img src={logo} className="h-6" alt="logo" />
                            </div>
                            <Form onSubmit={this.handleSubmit} processing={processingLogin} />
                        </div>
                    </div>
                </div>
                <Toasts />
            </div>
        );
    }
}

Login.propTypes = {
    login: PropTypes.object.isRequired,
    processLogin: PropTypes.func.isRequired,
};

const mapStateToProps = (state) => {
    const { login, toasts } = state;
    const props = { login, toasts };
    return props;
};

export default connect(
    mapStateToProps,
    actionCreators,
)(Login);
