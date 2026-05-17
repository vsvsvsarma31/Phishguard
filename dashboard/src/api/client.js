import axios from 'axios';

const apiClient = axios.create({
  baseURL: 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json',
  },
});

export const analyzeURL = async (url) => {
  const response = await apiClient.post('/analyze', { url });
  return response.data;
};

export const getHistory = async () => {
  const response = await apiClient.get('/history');
  return response.data;
};

export const getStats = async () => {
  const response = await apiClient.get('/stats');
  return response.data;
};
