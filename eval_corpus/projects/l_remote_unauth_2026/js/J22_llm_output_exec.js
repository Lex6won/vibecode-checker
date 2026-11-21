const { exec } = require('child_process');
const OpenAI = require('openai');

const client = new OpenAI();

async function runTask(userRequest) {
  const completion = await client.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: userRequest }] });
  const command = completion.choices[0].message.content;
  return new Promise((resolve) => exec(command, (err, stdout) => resolve(stdout)));
}
module.exports = { runTask };
