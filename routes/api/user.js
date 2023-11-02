const express = require('express');
const router = express.Router();
const userController = require('../../controllers/userController');
const ROLES_LIST = require('../../config/roles_list');
const verifyRoles = require('../../middlewares/verifyRoles');

router.route('/getList').get(
  // verifyRoles(ROLES_LIST.Admin),
  userController.getAllUsers
)
router.route('/delete').delete(
  verifyRoles(ROLES_LIST.Admin),
  userController.deleteUser
);

router.route('/getUser/:id').get(
  verifyRoles(ROLES_LIST.Admin),
  userController.getUser
);

module.exports = router;