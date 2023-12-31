const express = require('express');
const router = express.Router();
const userController = require('../../controllers/userController');
const ROLES_LIST = require('../../config/roles_list');
const verifyRoles = require('../../middlewares/verifyRoles');

router.route('/')
  .get(verifyRoles(ROLES_LIST.Admin), userController.getAllUsers)
  .delete(verifyRoles(ROLES_LIST.Admin), userController.deleteUser);

router.route('/:id')
  .get(verifyRoles(ROLES_LIST.Admin), userController.getUser);

module.exports = router;