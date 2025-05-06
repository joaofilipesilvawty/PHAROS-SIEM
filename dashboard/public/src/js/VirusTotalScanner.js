import React, { useState } from 'react';
import {
    Box,
    Button,
    Typography,
    Paper,
    CircularProgress,
    Alert,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Chip
} from '@mui/material';
import { CloudUpload, Security } from '@mui/icons-material';

const VirusTotalScanner = () => {
    const [file, setFile] = useState(null);
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);

    const handleFileChange = (event) => {
        setFile(event.target.files[0]);
    };

    const handleThreatAnalysis = async () => {
        if (!file) return;

        setLoading(true);
        setError(null);
        try {
            const formData = new FormData();
            formData.append('file', file);

            const response = await fetch('/api/virustotal/analyze-threat', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();
            setResult(data);
        } catch (err) {
            setError('Error analyzing threat: ' + err.message);
        } finally {
            setLoading(false);
        }
    };

    const getThreatLevelColor = (level) => {
        switch (level) {
            case 'critical': return 'error';
            case 'high': return 'warning';
            case 'medium': return 'info';
            case 'low': return 'success';
            default: return 'default';
        }
    };

    return (
        <Box sx={{ p: 3 }}>
            <Typography variant="h5" gutterBottom>
                Threat Analysis Scanner
            </Typography>

            <Paper sx={{ p: 2, mb: 3 }}>
                <Box sx={{ mb: 2 }}>
                    <input
                        accept="*/*"
                        style={{ display: 'none' }}
                        id="file-upload"
                        type="file"
                        onChange={handleFileChange}
                    />
                    <label htmlFor="file-upload">
                        <Button
                            variant="contained"
                            component="span"
                            startIcon={<CloudUpload />}
                            sx={{ mr: 2 }}
                        >
                            Upload File for Analysis
                        </Button>
                    </label>
                    {file && (
                        <Typography variant="body2" sx={{ mt: 1 }}>
                            Selected file: {file.name}
                        </Typography>
                    )}
                </Box>

                {file && (
                    <Button
                        variant="contained"
                        color="primary"
                        onClick={handleThreatAnalysis}
                        disabled={loading}
                        startIcon={<Security />}
                    >
                        Analyze Threat
                    </Button>
                )}
            </Paper>

            {loading && (
                <Box sx={{ display: 'flex', justifyContent: 'center', my: 3 }}>
                    <CircularProgress />
                </Box>
            )}

            {error && (
                <Alert severity="error" sx={{ mb: 3 }}>
                    {error}
                </Alert>
            )}

            {result && (
                <Paper sx={{ p: 2 }}>
                    <Typography variant="h6" gutterBottom>
                        Threat Analysis Results
                    </Typography>

                    <Box sx={{ mb: 2 }}>
                        <Typography variant="body1" gutterBottom>
                            Threat Level:
                            <Chip
                                label={result.threat_level.toUpperCase()}
                                color={getThreatLevelColor(result.threat_level)}
                                sx={{ ml: 1 }}
                            />
                        </Typography>
                        <Typography variant="body1" gutterBottom>
                            Detection Rate: {result.positives} / {result.total}
                        </Typography>
                        <Typography variant="body2" color="text.secondary" gutterBottom>
                            Analysis Date: {new Date(result.scan_date).toLocaleString()}
                        </Typography>
                        {result.permalink && (
                            <Button
                                href={result.permalink}
                                target="_blank"
                                rel="noopener noreferrer"
                                sx={{ mt: 1 }}
                            >
                                View Detailed Report
                            </Button>
                        )}
                    </Box>

                    <TableContainer>
                        <Table size="small">
                            <TableHead>
                                <TableRow>
                                    <TableCell>Scanner</TableCell>
                                    <TableCell>Threat Detected</TableCell>
                                    <TableCell>Details</TableCell>
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {Object.entries(result.scans || {}).map(([scanner, data]) => (
                                    <TableRow key={scanner}>
                                        <TableCell>{scanner}</TableCell>
                                        <TableCell>
                                            <Chip
                                                label={data.detected ? 'Yes' : 'No'}
                                                color={data.detected ? 'error' : 'success'}
                                                size="small"
                                            />
                                        </TableCell>
                                        <TableCell>{data.result || 'Clean'}</TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    </TableContainer>
                </Paper>
            )}
        </Box>
    );
};

export default VirusTotalScanner;