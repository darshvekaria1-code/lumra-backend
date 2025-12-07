/**
 * Personalized Learning Module using Neural Network Concepts
 * 
 * This module implements AI-powered personalized learning features:
 * - Learning style classification
 * - Adaptive difficulty adjustment
 * - Performance prediction
 * - Personalized study recommendations
 */

import OpenAI from "openai"

let openaiClient = null

/**
 * Initialize personalized learning module
 * @param {OpenAI} client - OpenAI client instance
 */
export function initializePersonalizedLearning(client) {
    openaiClient = client
    console.log("[Personalized Learning] ✅ Module initialized")
}

/**
 * Analyze student performance and classify learning style
 * @param {string} userId - User ID
 * @param {Array} performanceData - Array of performance records
 * @returns {Promise<Object>} Analysis with learning style and recommendations
 */
export async function analyzeStudentLearningStyle(userId, performanceData) {
    if (!openaiClient) {
        throw new Error("OpenAI client not initialized")
    }

    try {
        // Aggregate performance data
        const analysis = {
            totalQuestions: performanceData.length,
            correctAnswers: performanceData.filter(p => p.correct).length,
            averageTime: performanceData.reduce((sum, p) => sum + (p.timeSpent || 0), 0) / performanceData.length,
            topics: {},
            difficultyLevels: {}
        }

        // Analyze by topic
        performanceData.forEach(record => {
            const topic = record.topic || "General"
            if (!analysis.topics[topic]) {
                analysis.topics[topic] = { correct: 0, total: 0 }
            }
            analysis.topics[topic].total++
            if (record.correct) analysis.topics[topic].correct++

            const difficulty = record.difficulty || "medium"
            if (!analysis.difficultyLevels[difficulty]) {
                analysis.difficultyLevels[difficulty] = { correct: 0, total: 0 }
            }
            analysis.difficultyLevels[difficulty].total++
            if (record.correct) analysis.difficultyLevels[difficulty].correct++
        })

        // Use neural network (LLM) to classify learning style
        const learningStylePrompt = `Analyze this student's learning data and classify their learning style:

Performance Data:
- Total Questions: ${analysis.totalQuestions}
- Accuracy: ${((analysis.correctAnswers / analysis.totalQuestions) * 100).toFixed(1)}%
- Average Time per Question: ${analysis.averageTime.toFixed(1)} seconds
- Topic Performance: ${JSON.stringify(analysis.topics)}
- Difficulty Performance: ${JSON.stringify(analysis.difficultyLevels)}

Classify the student's learning style as one of:
1. Visual Learner - Prefers diagrams, charts, visual aids
2. Auditory Learner - Learns through listening and discussion
3. Kinesthetic Learner - Learns by doing, hands-on activities
4. Reading/Writing Learner - Prefers text-based materials

Also identify:
- Strengths (top 3 topics)
- Weaknesses (top 3 topics needing improvement)
- Recommended study approach
- Optimal difficulty level for next questions

Return JSON format:
{
    "learningStyle": "Visual Learner",
    "confidence": 0.85,
    "strengths": ["Topic1", "Topic2", "Topic3"],
    "weaknesses": ["Topic1", "Topic2", "Topic3"],
    "recommendedApproach": "Focus on visual diagrams and charts",
    "optimalDifficulty": "medium",
    "studyRecommendations": ["Recommendation1", "Recommendation2"]
}`

        const response = await openaiClient.chat.completions.create({
            model: process.env.PERSONALIZATION_MODEL || "gpt-4o-mini",
            messages: [
                {
                    role: "system",
                    content: "You are an expert educational psychologist specializing in learning style analysis for IB and IGCSE students."
                },
                {
                    role: "user",
                    content: learningStylePrompt
                }
            ],
            temperature: 0.3, // Lower temperature for more consistent analysis
            response_format: { type: "json_object" }
        })

        const learningStyleAnalysis = JSON.parse(response.choices[0].message.content)
        
        return {
            ...analysis,
            learningStyle: learningStyleAnalysis,
            analyzedAt: new Date().toISOString()
        }
    } catch (error) {
        console.error(`[Personalized Learning] ❌ Analysis failed: ${error.message}`)
        throw error
    }
}

/**
 * Generate adaptive question based on student performance
 * @param {string} topic - Subject topic
 * @param {Object} studentProfile - Student's learning profile
 * @param {Array} previousQuestions - Previously asked questions
 * @returns {Promise<Object>} Generated question with metadata
 */
export async function generateAdaptiveQuestion(topic, studentProfile, previousQuestions = []) {
    if (!openaiClient) {
        throw new Error("OpenAI client not initialized")
    }

    try {
        const difficulty = calculateOptimalDifficulty(studentProfile)
        
        const prompt = `Generate an IB/IGCSE ${topic} question for a student with these characteristics:

Student Profile:
- Learning Style: ${studentProfile.learningStyle?.learningStyle || "Mixed"}
- Strengths: ${studentProfile.learningStyle?.strengths?.join(", ") || "None specified"}
- Weaknesses: ${studentProfile.learningStyle?.weaknesses?.join(", ") || "None specified"}
- Current Difficulty Level: ${difficulty}
- Previous Performance: ${studentProfile.accuracy || 0}% accuracy

Previous Questions (avoid repetition):
${previousQuestions.slice(-5).map(q => `- ${q.question?.substring(0, 100)}...`).join("\n")}

Generate a question that:
1. Is at ${difficulty} difficulty level
2. Targets one of their weaknesses to help them improve
3. Is engaging and educational
4. Includes clear instructions
5. Has a detailed answer explanation

Return JSON format:
{
    "question": "The question text",
    "options": ["Option A", "Option B", "Option C", "Option D"],
    "correctAnswer": 0,
    "explanation": "Detailed explanation of the answer",
    "difficulty": "${difficulty}",
    "topic": "${topic}",
    "learningObjectives": ["Objective1", "Objective2"],
    "estimatedTime": 5
}`

        const response = await openaiClient.chat.completions.create({
            model: process.env.QUESTION_GENERATION_MODEL || "gpt-4o-mini",
            messages: [
                {
                    role: "system",
                    content: "You are an expert IB/IGCSE teacher. Generate high-quality, educational questions that help students learn effectively."
                },
                {
                    role: "user",
                    content: prompt
                }
            ],
            temperature: 0.7, // Slightly higher for creativity
            response_format: { type: "json_object" }
        })

        const question = JSON.parse(response.choices[0].message.content)
        
        return {
            ...question,
            generatedAt: new Date().toISOString(),
            adaptive: true
        }
    } catch (error) {
        console.error(`[Personalized Learning] ❌ Question generation failed: ${error.message}`)
        throw error
    }
}

/**
 * Calculate optimal difficulty based on student performance
 * Uses a simple neural network-like approach (adaptive algorithm)
 */
function calculateOptimalDifficulty(studentProfile) {
    const accuracy = studentProfile.accuracy || 50
    const recentPerformance = studentProfile.recentPerformance || []
    
    // Simple adaptive difficulty algorithm
    // If accuracy > 80%, increase difficulty
    // If accuracy < 60%, decrease difficulty
    // Otherwise, maintain current level
    
    let difficulty = studentProfile.currentDifficulty || "medium"
    
    if (accuracy > 80 && recentPerformance.length > 0) {
        const recentAccuracy = recentPerformance
            .slice(-10)
            .reduce((sum, p) => sum + (p.correct ? 1 : 0), 0) / Math.min(10, recentPerformance.length) * 100
        
        if (recentAccuracy > 80) {
            difficulty = difficulty === "easy" ? "medium" : difficulty === "medium" ? "hard" : "expert"
        }
    } else if (accuracy < 60) {
        difficulty = difficulty === "expert" ? "hard" : difficulty === "hard" ? "medium" : "easy"
    }
    
    return difficulty
}

/**
 * Predict student performance on upcoming topics
 * @param {string} userId - User ID
 * @param {Array} historicalData - Historical performance data
 * @param {Array} upcomingTopics - Topics to predict for
 * @returns {Promise<Object>} Predictions with confidence scores
 */
export async function predictStudentPerformance(userId, historicalData, upcomingTopics) {
    if (!openaiClient) {
        throw new Error("OpenAI client not initialized")
    }

    try {
        const prompt = `Based on this student's historical performance, predict their performance on upcoming topics:

Historical Performance:
${JSON.stringify(historicalData, null, 2)}

Upcoming Topics:
${upcomingTopics.join(", ")}

For each upcoming topic, predict:
1. Expected accuracy (0-100%)
2. Estimated time to master (hours)
3. Risk level (low/medium/high) - likelihood of struggling
4. Recommended study approach

Return JSON format:
{
    "predictions": [
        {
            "topic": "Topic Name",
            "expectedAccuracy": 75,
            "confidence": 0.8,
            "estimatedHours": 10,
            "riskLevel": "medium",
            "recommendations": ["Recommendation1", "Recommendation2"]
        }
    ],
    "overallRisk": "medium",
    "studyPlan": {
        "totalHours": 50,
        "priorityTopics": ["Topic1", "Topic2"],
        "schedule": "Study plan description"
    }
}`

        const response = await openaiClient.chat.completions.create({
            model: process.env.PREDICTION_MODEL || "gpt-4o-mini",
            messages: [
                {
                    role: "system",
                    content: "You are an expert educational data analyst specializing in performance prediction for IB/IGCSE students."
                },
                {
                    role: "user",
                    content: prompt
                }
            ],
            temperature: 0.2, // Very low for predictions
            response_format: { type: "json_object" }
        })

        const predictions = JSON.parse(response.choices[0].message.content)
        
        return {
            ...predictions,
            predictedAt: new Date().toISOString(),
            userId
        }
    } catch (error) {
        console.error(`[Personalized Learning] ❌ Prediction failed: ${error.message}`)
        throw error
    }
}

/**
 * Generate personalized study plan
 * @param {string} userId - User ID
 * @param {Object} studentProfile - Student's learning profile
 * @param {Array} curriculum - Available curriculum topics
 * @param {number} studyHours - Available study hours per week
 * @returns {Promise<Object>} Personalized study plan
 */
export async function generatePersonalizedStudyPlan(userId, studentProfile, curriculum, studyHours = 10) {
    if (!openaiClient) {
        throw new Error("OpenAI client not initialized")
    }

    try {
        const prompt = `Create a personalized study plan for an IB/IGCSE student:

Student Profile:
- Learning Style: ${studentProfile.learningStyle?.learningStyle || "Mixed"}
- Strengths: ${studentProfile.learningStyle?.strengths?.join(", ") || "None"}
- Weaknesses: ${studentProfile.learningStyle?.weaknesses?.join(", ") || "None"}
- Current Performance: ${studentProfile.accuracy || 0}% accuracy
- Available Study Time: ${studyHours} hours per week

Curriculum Topics:
${curriculum.map((topic, i) => `${i + 1}. ${topic.name} (${topic.difficulty || "medium"})`).join("\n")}

Create a weekly study plan that:
1. Prioritizes weak areas
2. Builds on strengths
3. Fits within ${studyHours} hours/week
4. Includes variety to maintain engagement
5. Has clear learning objectives
6. Includes practice and review sessions

Return JSON format:
{
    "weeklyPlan": [
        {
            "day": "Monday",
            "topics": ["Topic1", "Topic2"],
            "activities": ["Activity1", "Activity2"],
            "estimatedHours": 2,
            "learningObjectives": ["Objective1", "Objective2"]
        }
    ],
    "totalWeeklyHours": ${studyHours},
    "focusAreas": ["Area1", "Area2"],
    "milestones": [
        {
            "week": 1,
            "goal": "Goal description",
            "successCriteria": ["Criterion1", "Criterion2"]
        }
    ],
    "recommendedResources": ["Resource1", "Resource2"]
}`

        const response = await openaiClient.chat.completions.create({
            model: process.env.STUDY_PLAN_MODEL || "gpt-4o-mini",
            messages: [
                {
                    role: "system",
                    content: "You are an expert IB/IGCSE tutor. Create effective, personalized study plans that help students achieve their goals."
                },
                {
                    role: "user",
                    content: prompt
                }
            ],
            temperature: 0.5,
            response_format: { type: "json_object" }
        })

        const studyPlan = JSON.parse(response.choices[0].message.content)
        
        return {
            ...studyPlan,
            generatedAt: new Date().toISOString(),
            userId,
            validUntil: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() // Valid for 1 week
        }
    } catch (error) {
        console.error(`[Personalized Learning] ❌ Study plan generation failed: ${error.message}`)
        throw error
    }
}

/**
 * Check if personalized learning is available
 */
export function isPersonalizedLearningAvailable() {
    return openaiClient !== null
}



