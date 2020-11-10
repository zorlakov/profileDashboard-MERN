import { GET_POSTS, POST_ERROR } from './types';
import axios from 'axios';
// import { setAlert } from './alert';

// Get posts
export const getPosts = () => async (dispatch) => {
  try {
    const res = await axios.get('/api/posts');

    dispatch({
      type: GET_POSTS,
      payload: res.data,
    });
  } catch (err) {
    dispatch({
      type: POST_ERROR,
      payload: { msg: err.reposnse.statusText, status: err.response.status },
    });
  }
};
