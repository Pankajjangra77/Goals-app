const asyncHandler = require("express-async-handler");

const goalModel = require("../models/goalModel");
const userModel = require("../models/userModel");

// @desc  Get Goals
// @route GET /api/goals
// @access Private
const getGoals = asyncHandler(async (req, res) => {
    const goals = await goalModel.find({ user: req.user.id });
    res.status(200).json(goals);
});

// @desc  Set Goals
// @route POST /api/goals
// @access Private
const setGoal = asyncHandler(async (req, res) => {
    if (!req.body.text) {
        res.status(400);
        throw new Error("Please add a text field");
    }
    const goal = await goalModel.create({
        text: req.body.text,
        user: req.user.id,
    });
    res.status(200).json(goal);
});
// @desc  update Goal
// @route PUT /api/goals
// @access Private
const updateGoal = asyncHandler(async (req, res) => {
    const goal = await goalModel.findById(req.params.id);
    if (!goal) {
        res.status(400);
        throw new Error("Goal not found");
    }

    const user = await userModel.findById(req.user.id);

    // Check for user
    if (!user) {
        res.status(401);
        throw new Error("User not found");
    }

    // Make sure the logged in user matches the goal user
    if (goal.user.toString() !== user.id) {
        res.status(401);
        throw new Error("user not authorised");
    }

    const updatedGoal = await goalModel.findByIdAndUpdate(
        req.params.id,
        req.body,
        {
            new: true,
        }
    );
    res.status(200).json(updatedGoal);
});

// @desc  Delete Goals
// @route DELETE /api/goals
// @access Private
const deleteGoal = asyncHandler(async (req, res) => {
    const goal = await goalModel.findById(req.params.id);
    if (!goal) {
        res.status(400);
        throw new Error("Goal not found");
    }

    const user = await userModel.findById(req.user.id);

    // Check for user
    if (!user) {
        res.status(401);
        throw new Error("User not found");
    }

    // Make sure the logged in user matches the goal user
    if (goal.user.toString() !== user.id) {
        res.status(401);
        throw new Error("user not authorised");
    }

    await goal.remove();

    res.json({
        message: "Goal deleted successfully",
        id: req.params.id,
    });
});

module.exports = {
    getGoals,
    setGoal,
    updateGoal,
    deleteGoal,
};
