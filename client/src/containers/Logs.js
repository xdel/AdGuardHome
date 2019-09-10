import { connect } from 'react-redux';
import { getFilteringStatus, setRules, addSuccessToast, getClients } from '../actions';
import { getLogs, getLogsConfig } from '../actions/queryLogs';
import Logs from '../components/Logs';

const mapStateToProps = (state) => {
    const { queryLogs, dashboard, filtering } = state;
    const props = { queryLogs, dashboard, filtering };
    return props;
};

const mapDispatchToProps = {
    getLogs,
    getFilteringStatus,
    setRules,
    addSuccessToast,
    getClients,
    getLogsConfig,
};

export default connect(
    mapStateToProps,
    mapDispatchToProps,
)(Logs);
