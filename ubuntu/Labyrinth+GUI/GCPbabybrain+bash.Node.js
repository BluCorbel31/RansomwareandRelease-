//bash #! gcloud functions deploy makeDecision --runtime=nodejs14 --trigger-http --allow-unauthenticated

//Node.js
exports.makeDecision = (req, res) => {
  try {
    const answers = req.body.answers; // Assuming answers is an array of true/false values
    // Your decision-making logic here
    const trueCount = answers.filter(answer => answer === true).length;
    // Example action based on the number of true answers
    const action = (trueCount >= 3) ? 'Take action A' : 'Take action B';

    res.status(200).json({ action });
  } catch (error) {
    console.error('Error occurred while making decision:', error);
    res.status(500).send('Internal Server Error');
  }
};