const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const auth = require('../../middleware/auth');
const User = require('../../models/User');
const Post = require('../../models/Post');
const Profile = require('../../models/Profile');

// @route POST api/posts
// @desc Create a post
// @access Private
router.post(
  '/',
  [auth, [check('text', 'Text is required').not().isEmpty()]],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    try {
      const user = await User.findById(req.user.id).select('-password');
      const newPost = new Post({
        text: req.body.text,
        name: user.name,
        avatar: user.avatar,
        user: req.user.id,
      });
      const post = await newPost.save();
      res.json(post);
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error!');
    }
  }
);

// @route GET api/posts
// @desc Get all posts
// @access Private
router.get('/', auth, async (req, res) => {
  try {
    // Return all posts and sort them most recent come first (-1), 1 is oldest first
    const posts = await Post.find().sort({ date: -1 });
    res.json(posts);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error!');
  }
});

// @route GET api/posts/:id
// @desc Get post by ID
// @access Private
router.get('/:id', auth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ msg: '404: Post not found' });
    res.json(post);
  } catch (err) {
    console.error(err.message);
    if (err.kind === 'ObjectId')
      return res.status(404).json({ msg: '404: Post not found' });

    res.status(500).send('Server error!');
  }
});

// @route DELETE api/posts:id
// @desc Delete post by ID
// @access Private
router.delete('/:id', auth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ msg: '404: Post not found' });

    // The user that is deleting the post must be the post creator
    if (post.user.toString() !== req.user.id) {
      return res
        .status(401)
        .json({ msg: 'ERROR! You are not authorized for this action!' });
    }

    await post.remove();

    res.json({ msg: 'Post successfully removed!' });
  } catch (err) {
    console.error(err.message);
    if (err.kind === 'ObjectId')
      return res.status(404).json({ msg: '404: Post not found' });
    res.status(500).send('Server error!');
  }
});

// @route PUT api/posts/like/:id
// @desc Like a post
// @access Private
router.put('/like/:id', auth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);

    // Check if post has been liked previously by the user
    if (
      post.likes.filter((like) => like.user.toString() === req.user.id).length >
      0
    ) {
      return res.status(400).json({ msg: 'Post has already been liked.' });
    }
    post.likes.unshift({ user: req.user.id });

    await post.save();

    res.json(post.likes);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error!');
  }
});

// @route PUT api/posts/unlike/:id
// @desc Unlike a post you've previously liked
// @access Private
router.put('/unlike/:id', auth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);

    // Check if post has been liked previously by the user
    if (
      post.likes.filter((like) => like.user.toString() === req.user.id)
        .length === 0
    ) {
      return res.status(400).json({ msg: 'Post has not been liked yet.' });
    }
    // Get remove index and then remove post
    const removeIndex = post.likes
      .map((like) => like.user.toString())
      .indexOf(req.user.id);
    post.likes.splice(removeIndex, 1);
    await post.save();

    res.json(post.likes);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error!');
  }
});

// @route POST api/posts/comment/:id
// @desc Comment on a post (post id)
// @access Private
router.post(
  '/comment/:id',
  [auth, [check('text', 'Text is required').not().isEmpty()]],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    try {
      const user = await User.findById(req.user.id).select('-password');
      const post = await Post.findById(req.params.id);

      const newComment = {
        text: req.body.text,
        name: user.name,
        avatar: user.avatar,
        user: req.user.id,
      };
      post.comments.unshift(newComment);
      await post.save();
      res.json(post.comments);
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error!');
    }
  }
);

// @route DELETE api/posts/comment/:id/:comment_id
// @desc Delete a comment
// @access Private
router.delete('/comment/:id/:comment_id', auth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);

    // Take the comment we want to delete
    const comment = post.comments.find(
      (comment) => comment.id === req.params.comment_id
    );
    // Check if the comment exists
    if (!comment) {
      return res.status(404).json({ msg: '404: Comment not found!' });
    }
    // Check if the user deleting the comment is the one that posted it
    if (comment.user.toString() !== req.user.id) {
      return res.status(401).json({ msg: 'Not authorized for this action!' });
    }
    const removeIndex = post.comments
      .map((comment) => comment.user.toString())
      .indexOf(req.user.id);

    post.comments.splice(removeIndex, 1);
    await post.save();
    res.json(post.comments);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

module.exports = router;
