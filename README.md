# Secure Password Handling

**Learning Objective:** Implement secure password handling

---

## Why storing plain-text passwords is dangerous

Imagine you are building a web app where users create accounts with a password. The simplest approach might seem to be saving the *exact* password each user enters, then comparing it to their entry at login. However, this would be like storing everyone's valuables in a safe with the key taped to the front—if someone opens the safe, they immediately have access to everything.

If your database is ever breached—through a cyberattack, a configuration mistake, or any form of unauthorized access—all user passwords would be exposed in seconds. Globally, there are frequent reports of breaches where millions of accounts were compromised simply because passwords had been stored this way.

Consider these real-world risks:

- **Database breach:** An attacker exploits a vulnerability, downloads your user table, and instantly sees every password.
- **Internal access:** Any administrator with database privileges could view all user passwords.
- **Password reuse dangers:** Many people, regardless of country or region, use the same password for multiple sites. A breach in one place puts users at risk on other platforms—banking apps, email, or professional services.

> 💡 As a developer, you are responsible for creating systems where it is nearly impossible for anyone—inside or outside your organization—to recover the original password, even if they gain access to your user database.

tktk asset: Illustration showing a "safe" with valuables labeled "passwords," and a key taped to the outside, contrasted with a locked safe with no visible key.

---

## How attackers compromise vulnerable password systems

Attackers use a variety of techniques to steal or guess passwords, especially if password handling is weak. Here are the most common:

- **Brute force attacks:** The attacker tries every possible password combination, which works especially well on short or common passwords.
- **Dictionary attacks:** The attacker uses a list of likely passwords (like "password," "qwerty," or "ilovecode") to guess what users picked.
- **Rainbow table attacks:** If passwords are hashed using fast algorithms (like MD5 or SHA-256 on their own), attackers use large precomputed tables that match hashes to common passwords, making it fast to reverse-engineer the password from its hash.

**Example:** If the password *music2024* is stored as plain text or as a simple hash, a hacker can quickly test whether this password is used by any account. If hashes are not uniquely protected, even more damage is possible—every user who chose the same password gets exposed at once.

> ⚠ If passwords are not protected using secure methods, attackers can compromise hundreds, thousands, or even millions of accounts rapidly—often before you even know your data has been leaked.

tktk asset: Diagram showing three attack types targeting a password database: brute force, dictionary, and rainbow tables.

---

## Using hashing and salting to defend against attacks

### What is hashing?

A *hash function* takes some input data—like a user's password—and mathematically transforms it into a unique string of characters called a *hash*. This process is one-way: you can turn a password into a hash, but not the other way around.

Each time a user sets a password:
- The password is hashed;
- Only the hash is stored;
- When the user logs in, the entered password is hashed using the same algorithm, and the hashes are compared.

**Analogy:** Imagine placing a blank sheet in a paper shredder. You can shred it (hash it), but you can never reassemble every tiny piece perfectly back into the original sheet (reverse the hash).

> 📚 A *hash* is a fixed-size string of characters produced by a mathematical function. Think of it as a digital fingerprint—unique to the input, but impossible to turn back into the exact input.

**Sample code:**

Using SHA-256 in Node.js (DO NOT use for password storage on its own!):

server/security/hash-example.js

javascript
const crypto = require('crypto');

const password = 'music2024';

const hash = crypto.createHash('sha256').update(password).digest('hex');
console.log(hash); // Prints: Hash string, e.g., 'e1ffe...'

But, using SHA-256 alone is not safe for user passwords due to its speed and vulnerability to rainbow table attacks.

### What is salting?

A *salt* is a unique, random value added to each password before hashing. Salts make it almost impossible for attackers to use precomputed lists (like rainbow tables) because the same password with different salts results in different hashes.

Imagine two users choose "music2024" as their password. Without salting, their password hashes would be identical, making it easy for an attacker to spot and compromise multiple users at once. With salting, both hashes are different—even though the passwords are not.

tktk asset: Two users each setting the same password; with and without salt, their hashes are identical or different (add callouts to highlight uniqueness).

> 🏆 Salting prevents attackers from using "lookups" to break into accounts and ensures every user gets a unique form of protection, even if passwords repeat.

### Why bcrypt and similar algorithms?

Modern authentication relies on *computationally expensive* (slow) hashing functions such as bcrypt, scrypt, or Argon2. These are designed to resist brute force attacks by making each password guess costly in time and resources. Bcrypt is widely adopted, easy to use in Node.js, and automatically manages salting for you.

> ♻️ Bcrypt's strength lies in being slow and adaptive: you can make it slower over time as computers get faster, maintaining strong protection.

---

## Interacting with bcrypt in Node.js

Let's put this into practice. Here's how you can use bcrypt in your own authentication system built with Node.js.

**Install bcrypt:**

shell
npm install bcrypt

**Hashing and verifying a password:**

auth-example.js

javascript
const bcrypt = require('bcrypt');

// Define the password to hash
const password = 'music2024';

// Set the cost factor for hashing
const saltRounds = 10;

bcrypt.hash(password, saltRounds)
  .then((hash) => {
    console.log('Hashed password:', hash);

    // Now verify the password
    return bcrypt.compare(password, hash);
  })
  .then((result) => {
    if (result) {
      console.log('Password is correct!');
    } else {
      console.log('Incorrect password.');
    }
  })
  .catch((error) => {
    console.error('Error:', error);
  });

tktk asset: Screenshot of resulting console output for both successful and failed verification.

**Key points:**
- *saltRounds* controls how slow the hashing process is. The higher the number, the more secure (within reason), but the slower.
- *bcrypt.hash()* automatically creates a new, random salt for every password.
- Only the hash is stored; the plain password is never saved in the database.

---

## Step-by-step: Creating your own secure password utility

Let's create a reusable module for secure password handling, as you would for a real user authentication system.

**1. hashPassword function**

<code class="filepath">auth-utils.js</code>

javascript
const bcrypt = require('bcrypt');

/**
 * Hash a plain text password using bcrypt.
 * @param {string} plainPassword - The user's password to hash.
 * @returns {Promise<string>} - The hashed password, ready for storage.
 */
function hashPassword(plainPassword) {
  const saltRounds = 12; // Recommended baseline for modern security
  return bcrypt.hash(plainPassword, saltRounds);
}

module.exports = { hashPassword };

**2. verifyPassword function**

<code class="filepath">auth-utils.js</code>

javascript
/**
 * Compare a plain password to a stored hash.
 * @param {string} plainPassword
 * @param {string} hashFromDB
 * @returns {Promise<boolean>}
 */
function verifyPassword(plainPassword, hashFromDB) {
  return bcrypt.compare(plainPassword, hashFromDB);
}

module.exports = { hashPassword, verifyPassword };

> 🧠 Try passing several different passwords—including the same one more than once—and observe the hashes. They should all look unique, thanks to salt.

---

## Best practices for storing and verifying passwords

- **Never store plain text passwords**—not even temporarily.
- **Always use a slow hash function with built-in salting**—bcrypt, scrypt, or Argon2.
- **Increase salt rounds over time** as hardware gets faster—bcrypt simplifies this.
- **Store only the hash output**—this contains the salt and all necessary parameters.
- **Hash passwords on the server**—never trust the browser or client-side JavaScript to do this.
- **Always use library compare methods**—such as bcrypt's compare function—instead of writing your own.
- **Regenerate salt on password updates**—bcrypt manages this when you hash a new password.

> 🧠 *Discussion prompt*: Why is it not enough to use a fast hash algorithm like SHA-256 (even with a salt) for password storage?

tktk asset: Visual checklist of best practices for password storage.

---

## Activity: Implement and test secure password hashing in Node.js

**Purpose:**  
Practice implementing secure password handling functions. Test firsthand how modern password storage techniques protect both users and your application.

**Deliverable:**  
A working Node.js authentication utility with thorough console tests showing both successful and failed password verification.

**Instructions:**

1. **Set up your project**  
   - Open your code editor.
   - In your <code class="filepath">~/code/ga/labs</code> directory, create a new Node.js project.  
   - In the project folder, run:

     shell
     npm install bcrypt

2. **Create auth-utils.js**  
   - In your project, add <code class="filepath">auth-utils.js</code>.  
   - Implement *hashPassword* and *verifyPassword* as shown above.

3. **Test your functions in test-auth.js**  
   - Create <code class="filepath">test-auth.js</code>.
   - Write code to:
     - Hash a sample password (for example, 'blueSky2024').
     - Attempt to verify the hash with the correct password.
     - Attempt to verify with an incorrect password.
     - Print appropriate success or failure messages.

4. **Explore further:**  
   - Hash the *same* password multiple times in a row.  
   - Compare the hashes—are they different?  
   - What does this tell you about how bcrypt protects your users?

5. **Discussion prompts:**  
   - Why is it important that identical passwords generate different hashes each time when using bcrypt?
   - What risks still exist if someone uses a fast hash like SHA-256 (even with a salt)?
   - If you were building an app for millions of users, how would you balance password security with system performance?

> ❓ How might you adapt your approach if your application required scalable authentication for a global user base with millions of users? What would you prioritize to maintain both security and usability?

> 😎 Remember, proper password storage is a cornerstone of user trust. Users expect that their data will remain private, even if systems are attacked.

tktk asset: Sample terminal screenshot with clear output for successful and failed password checks; code directory structure example.

---

## Instructor guide

This microlesson supports learners in understanding the real-world implications of secure password handling and translating that understanding into applied skill. Learners will not only implement code but also explore real attack scenarios and make explicit connections to global user risks.

**Suggested delivery:**

- Begin with a relatable real-world analogy, such as the "safe with the key taped outside."
- Engage learners in a quick discussion: "What could go wrong if plain password storage is used?"
- Work through code examples live, narrating each step in the hashing and verification process.
- Use the provided activity as a hands-on challenge. Circulate (or check in virtually) to prompt learners to notice that even the same passwords generate different hashes (emphasizing the purpose of salting).
- Use the discussion prompts to deepen their thinking, especially on the global implications of poor authentication.

**Knowledge check/discussion answers:**

- *Why is it not enough to use a fast hash algorithm like SHA-256, even with a salt?*  
  Because fast hashes let attackers test vast numbers of passwords each second. Even when salted, an attacker can brute-force millions of guesses rapidly. Slow, adaptive hashes like bcrypt dramatically reduce attacker speed and make mass attacks much less likely to succeed.

- *Why must identical passwords create different hashes each time with bcrypt?*  
  If two users share a password, and the hashes are identical, an attacker can exploit this. Unique, salted hashes protect against this by ensuring that even shared passwords are stored and protected independently.

- *If scaling to millions of users, what would you prioritize?*  
  Balance the salt rounds to ensure strong security without making authentication unacceptably slow. Monitor system performance and automate increasing salt rounds as hardware improves. Consider rate limiting and distributed authentication systems for scale.

**Activity sample solution:**

- *hashPassword* and *verifyPassword* are defined in <code class="filepath">auth-utils.js</code>.
- In <code class="filepath">test-auth.js</code>, the learner hashes 'blueSky2024', verifies both the correct and incorrect passwords, and prints success/failure.
- Learner observes that hashing 'blueSky2024' multiple times produces different hashes every time, confirming salting is active.

**Sample output:**

shell
Hashed password: $2b$12$Ezg... (example)
Password is correct!
Password is incorrect.
Another hash: $2b$12$Lvn...
Are the hashes equal? false

Encourage learners to share their output and observations with the group for real-time feedback and peer learning.
