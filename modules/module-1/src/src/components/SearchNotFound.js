import PropTypes from 'prop-types';
// material
import { Paper } from '@mui/material';

// ----------------------------------------------------------------------

SearchNotFound.propTypes = {
  searchQuery: PropTypes.string,
};

export default function SearchNotFound({ searchQuery = '', ...other }) {
  return (
    <Paper {...other}>
      {/* Remediation (Reflected XSS): the search query used to be rendered via
          dangerouslySetInnerHTML with no sanitization (attack-manuals/module-1/
          01-Reflected XSS.md - <img src=a onerror=alert('xss')> in the search
          bar). A search query has no legitimate reason to contain HTML, so it
          is rendered as plain text instead - React escapes it automatically. */}
      <p style={{ textAlign: 'center' }}>Results for <strong>{searchQuery}</strong></p>
    </Paper>
  );
}
