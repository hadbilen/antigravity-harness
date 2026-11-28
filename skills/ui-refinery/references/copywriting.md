# copy-polish

> UI Refinery: Rules for AI Coding Agents. Copy & Text module

> Part of the `ui-refinery` system. Read together with the `ui-refinery` core skill (`~/.gemini/config/skills/ui-refinery/SKILL.md`). This module deep-dives the copy and text concern: headlines, CTAs, tone, value propositions, and the patterns that make AI-written prose easy to spot. It references core rules by number and never duplicates or renumbers them. Load on demand when explicitly writing or auditing marketing copy, product copy, landing-page text, or de-AI prose rewrites.

## How to use this skill

- Load on demand alongside the `ui-refinery` core skill (`~/.gemini/config/skills/ui-refinery/SKILL.md`) when explicitly writing or auditing marketing prose, landing-page copy, or de-AI text rewrites (do not co-load automatically on routine UI layout edits). The core holds the mechanism (the purpose test, the three tiers, the Delivery Gate) and the hard bans (R-02, R-15, R-16, R-17, R-18, R-36, R-38). This module holds copy-specific depth that the core does not.
- Every pattern has the same shape: **The pattern**, **Why it reads as AI**, **Before** (the slop), **After** (the fix), with the governing core rule cited as R-XX.
- Two rules apply to everything below:
  - **Never invent facts** (R-17, R-36, R-38). A rewrite adds no fact, name, number, date, quote, or citation that is not in the source text or supplied by the user. Specificity comes from the source or the user, not from the rewrite. If a sentence needs real detail to work, ask for it or write the plain version without it.
  - **Do not over-sterilize.** Avoiding AI patterns is half the job. Copy with no voice is as obviously machine-made as copy full of AI tells (R-37). When a user supplies a voice, keep it.
- The Delivery Gate in the core remains the gate. The "Copywriting Skill Checklist" at the end of this file is the copy-specific supplement to run alongside it.

## Tone & Voice

### Empty AI Vocabulary

- **The pattern:** verbs and abstract nouns stacked to sound impressive without saying anything: *unlock, elevate, empower, delve, showcase, testament, landscape (abstract), journey, robust, game-changer, next-level, seamless, cutting-edge, revolutionary*.
- **Why it reads as AI:** these words appear far more often in machine-written text. They signal intent to impress, not intent to inform, and they are the fastest way to mark a page as AI-generated.
- **Before:**
  > Unlock the power of seamless collaboration to elevate your team's journey to the next level.
- **After:**
  > Work with your team in one shared space.
- **Rule:** R-02 (no marketing buzzwords or generic hype), R-16 (natural human prose), R-36 (no fabricated claims).

### Significance Inflation

- **The pattern:** "the future of X", "marking a pivotal moment", "a testament to", "revolutionizing", "a new era of".
- **Why it reads as AI:** the claim has no evidence behind it, and the sentence reads the same no matter what the product does. It is ceremony where content should be.
- **Before:**
  > Our platform is marking a pivotal moment in the evolution of team productivity, ushering in a new era of work.
- **After:**
  > Our platform cuts the time your team spends on status meetings.
- **Rule:** R-36 (no fabricated claims), C-5 (evidence over claims).

### Empty Claims and Social Proof with No Evidence

- **The pattern:** "Trusted by thousands of teams", "industry-leading", "world-class", "loved by customers everywhere", with nothing named or verifiable.
- **Why it reads as AI:** a trust claim without evidence is a confession. It fills the space a real customer name, a real number, or a real use case should occupy.
- **Before:**
  > Trusted by thousands of teams worldwide. Industry-leading technology loved by customers everywhere.
- **After:**
  > Used by the support teams at [customer names, only if real]. If there are no real customers to name, cut the claim entirely.
- **Rule:** R-17 (data and numbers), R-18 (testimonials), R-36 (no fabricated claims), C-5.

### Weasel Attributions

- **The pattern:** "Experts say", "industry observers", "people report", "leading analysts believe", with no one named.
- **Why it reads as AI:** the attribution exists to make an unsourced claim feel authoritative. If the authority is real, name it; if not, the claim does not get a costume.
- **Before:**
  > Experts say this approach dramatically improves conversion.
- **After:**
  > [Name the source or cut the sentence. Example with a real source: "In a 2024 study by [named firm], this approach improved conversion by [real figure]."]
- **Rule:** R-36, C-5.

### Persuasive Authority Tropes

- **The pattern:** "at its core", "the real question is", "what really matters", "fundamentally", "the deeper issue", "the heart of the matter".
- **Why it reads as AI:** these phrases pretend to cut through noise to a deeper truth, then restate an ordinary point with extra ceremony.
- **Before:**
  > At its core, what really matters is whether your team can move faster.
- **After:**
  > Whether your team can move faster depends on how quickly you can merge changes.
- **Rule:** R-36.

### Chatbot Closers

- **The pattern:** "I hope this helps!", "Let me know if you have any questions", "Would you like me to expand on this?", "You're welcome!".
- **Why it reads as AI:** these are conversation artifacts, not copy. They appear when model chat output is pasted straight into a deliverable.
- **Before:**
  > Here is an overview of our pricing. I hope this helps! Let me know if you'd like me to break down any tier.
- **After:**
  > Here is our pricing. The Starter tier includes three seats and community support.
- **Rule:** R-36.

### Fake-Candid Openers

- **The pattern:** "Honestly?", "Let's be honest", "Here's the thing", "Real talk", as a theatrical pause before an ordinary point.
- **Why it reads as AI:** a person being honest usually just says the thing. The pause-and-reveal is manufactured intimacy.
- **Before:**
  > Is it worth the price? Honestly? It depends on how often you'll use it.
- **After:**
  > Whether it is worth the price depends on how often you'll use it.
- **Rule:** R-36.

### Signposting Announcements

- **The pattern:** "Let's dive in", "Here's what you need to know", "In this article we'll explore", "Without further ado".
- **Why it reads as AI:** announcing what you are about to do instead of doing it is meta-commentary. It slows the reader and gives the text a tutorial-script feel.
- **Before:**
  > Let's dive into how caching works in Next.js. Here's what you need to know.
- **After:**
  > Next.js caches data at multiple layers, including request memoization, the data cache, and the router cache.
- **Rule:** R-36.

### Temporal Runway Cliches

- **The pattern:** opening a piece, section, or paragraph with a sweeping temporal generalization: "In today's fast-paced world", "In an era of rapid technological disruption", "In today's ever-evolving digital landscape", "In an increasingly connected world".
- **Why it reads as AI:** it is empty runway that delays the actual claim before stating an ordinary fact.
- **Before:**
  > In today's fast-paced digital landscape, engineering teams struggle to keep internal documentation fresh and accurate.
- **After:**
  > Engineering teams struggle to keep internal documentation fresh and accurate.
- **Rule:** R-16, R-36.

### All-Caps Emphasis

- **The pattern:** a whole sentence, clause, or phrase in ALL CAPS inside a paragraph to shout emphasis: "The launch is ready and WE NEED TO MOVE NOW before the window closes."
- **Why it reads as AI:** caps-as-emphasis is a blunt instrument the model reaches for to manufacture urgency instead of writing emphasis into the sentence. In long text it reads as shouting, and it flattens the real peaks by making everything loud.
- **Before:**
  > This is our last chance to win this customer, and WE MUST ACT IMMEDIATELY before they choose a competitor.
- **After:**
  > This is our last chance to win this customer. If we do not respond today, they will choose a competitor.
- **Rule:** R-36. (R-06 covers uppercase labels with wide tracking as a design choice; this pattern is the prose case: caps inside a paragraph doing the emphasis work.)
- **Not a ban:** a genuine headline, a deliberately shouted line in a voice that shouts, or a single all-caps word used once as an accent can keep its caps. The tell is caps used sentence after sentence to do the emphasis the words should do. Minimize, do not strip every cap.

### Actorless Passive

- **The pattern:** the passive voice with the actor deleted: "the decision was made to sunset the free tier", "the pricing page has been updated", "mistakes were made".
- **Why it reads as AI:** the model does not know who acted, so it writes around it. The team that shipped the thing does know, and says so. Deleting the actor also quietly removes accountability from the sentence, which is why the shape survives in corporate copy and nowhere else.
- **Before:**
  > The pricing page was updated to reflect the new tiers.
- **After:**
  > We rewrote the pricing page to show the new tiers.
- **Rule:** R-16 (text must feel natural and human).
- **Not a ban:** passive is the right choice when the actor is unknown, irrelevant, or deliberately withheld ("the server was restarted at 03:00"), and when the object is the real subject of the paragraph. The tell is passive chosen by default, page after page, with an actor that was available the whole time.

### Inanimate Subject, Human Verb

- **The pattern:** an abstraction given agency: "the data tells us", "the design decides", "the complaint becomes a fix", "the roadmap wants to focus on retention".
- **Why it reads as AI:** it sounds active while naming nobody, so it passes a passive-voice check and still hides the actor. It also flatters the product, since a dashboard that "understands" is doing something no dashboard does.
- **Before:**
  > The dashboard understands what your team needs and surfaces the right numbers.
- **After:**
  > The dashboard opens on the three metrics your team checks every morning.
- **Rule:** R-02 (no hype), R-16 (natural human prose and specific language over claims).
- **Not a ban:** ordinary product verbs are fine, and so are established idioms. "The report shows", "the form submits", "the filter narrows the list" describe what the thing does. The tell is a verb that needs a mind behind it: understands, knows, decides, wants, believes, cares.

### Chatbot Openers

- **The pattern:** "Great question!", "Certainly!", "Absolutely!", "I'd be happy to help!", or ungrounded praise for the reader's idea before any answer.
- **Why it reads as AI:** conversation artifacts pasted straight into a deliverable (`check_synthetic_markers.py` `4.1`).
- **Before:**
  > Great question! Choosing the right plan can feel overwhelming, but I'm happy to walk you through it. The Starter plan covers three seats.
- **After:**
  > The Starter plan covers three seats.
- **Rule:** R-02.

### Teaser Reveals

- **The pattern:** a one-word question or colon label placed to stage suspense before an ordinary fact: "The result?", "The kicker:", "The best part?", "Spoiler:", "Plot twist:".
- **Why it reads as AI:** manufactures suspense where the prior sentence could state the effect directly.
- **Before:**
  > We moved the build to a single cache layer. The result? Deploys that finish in under a minute.
- **After:**
  > After we moved the build to a single cache layer, deploys finish in under a minute.
- **Rule:** R-02.
- **Not a ban:** a colon introducing a list, definition, or quotation is ordinary punctuation.

### Scene-Setting Hypotheticals

- **The pattern:** generic imagined openings delaying the subject: "Picture this:", "Imagine a world where", "Let's say you're a busy founder".
- **Why it reads as AI:** substitutes an invented cliché for a real example and fits any product.
- **Before:**
  > Picture this: it's Monday morning, your inbox is overflowing, and your team is waiting on you. Our inbox view sorts blocking messages to the top.
- **After:**
  > The inbox view sorts messages that block a teammate to the top.
- **Rule:** R-02, R-16.
- **Not a ban:** a real scenario supplied by the user or a worked example with concrete details.

### Faux-Intimate Reader Address

- **The pattern:** claiming to know what the reader thinks or lived: "You might be wondering", "We've all been there", "Sound familiar?", "If you're like most people".
- **Why it reads as AI:** simulates rapport to set up an unasked question.
- **Before:**
  > You might be wondering how this works with your tools. We've all been there. It imports projects from Jira and Linear.
- **After:**
  > It imports projects from Jira and Linear.
- **Rule:** R-02.

### Audience Sweep

- **The pattern:** naming both ends of a scale to claim universal fit: "Whether you're a seasoned pro or just starting out", "Whether you run a startup or an enterprise".
- **Why it reads as AI:** avoids naming the actual audience so the copy reads identically across products.
- **Before:**
  > Whether you're a seasoned developer or just getting started, our CLI has you covered.
- **After:**
  > [Name the user-supplied audience, or cut the clause and state what the CLI does.]
- **Rule:** R-16.

### Straw-Man Setup

- **The pattern:** inventing an unnamed group to disagree with: "Many people think X. But the reality is Y.", "Conventional wisdom says", "Most teams get this wrong".
- **Why it reads as AI:** stages an ordinary point as an unchecked correction against an unnamed opponent.
- **Before:**
  > Most people think onboarding is about tutorials. The truth is, it's about momentum.
- **After:**
  > [Cite the real study or state the team's own observation directly.]
- **Rule:** R-36, C-5.
- **Not a ban:** correcting a named, cited survey, documented myth, or the user's stated belief.

### Copula Avoidance

- **The pattern:** ceremonial verbs ("serves as", "stands as", "functions as", "boasts", "offers", "represents") used repeatedly where plain "is" or "has" belongs (`check_synthetic_markers.py` `2.2`).
- **Why it reads as AI:** inflates sentence length and ceremony without adding information.
- **Before:**
  > The dashboard serves as a central hub for reports and boasts filters for date, owner, and status.
- **After:**
  > The dashboard is where reports live. It has filters for date, owner, and status.
- **Rule:** R-02.
- **Not a ban:** literal senses ("a relay functions as a switch", "a store offers a discount").

### Vague Quantifiers

- **The pattern:** "countless", "a myriad of", "a plethora of", "numerous", "a wide range of" substituting for a real number or list.
- **Why it reads as AI:** sounds large while committing to zero verifiable specifics.
- **Before:**
  > Choose from a myriad of integrations to streamline countless workflows.
- **After:**
  > [Name real integrations supplied by the user, or point to the integrations list.]
- **Rule:** R-16, R-17.

### Nominalized Verbs

- **The pattern:** turning an action into a noun propped up by a weak verb: "conduct an analysis of", "perform the implementation of", "provide assistance with", "carry out an evaluation of".
- **Why it reads as AI:** stiff procurement-document register where one direct verb works.
- **Before:**
  > Our team will conduct an analysis of your setup and provide assistance with the implementation.
- **After:**
  > We will review your setup and help you install it.
- **Rule:** R-02.
- **Not a ban:** nouns naming a concrete artifact ("the analysis is attached", "the migration takes an hour").

## Rhythm & Structure

### Rule of Three Overuse

- **The pattern:** every idea forced into a group of three to sound complete: "innovation, inspiration, and insights".
- **Why it reads as AI:** real lists have the number of items the content requires. A forced trio is a rhythm tell, and it appears across every section at once.
- **Before:**
  > Attendees can expect keynote sessions, panel discussions, and networking opportunities. They'll leave with innovation, inspiration, and industry insights.
- **After:**
  > The event includes talks, panels, and time for informal networking between sessions.
- **Rule:** R-05 (page structure), R-16 (natural prose rhythm), R-36.

### Negative Parallelism and Tailing Negations

- **The pattern:** "It's not just X, it's Y", "Not only X, but also Y", and clipped fragments tacked on as emphasis: "no guessing", "no wasted motion".
- **Why it reads as AI:** the construction is a formula the model reaches for to sound emphatic, whether or not the emphasis is earned.
- **Before:**
  > It's not just a dashboard, it's a command center. The options come from the selected item, no guessing.
- **After:**
  > The dashboard shows the data you select. The options come from the selected item without forcing you to guess.
- **Rule:** R-36.

### Aphorism Formulas

- **The pattern:** "X is the language of Y", "X is the currency of Z", "X is not a tool but a mirror", "Efficiency becomes a trap when".
- **Why it reads as AI:** a reusable formula that sounds profound without adding precision. It gestures at a point instead of stating it.
- **Before:**
  > Symmetry is the language of trust. Efficiency becomes a trap when teams forget the human layer.
- **After:**
  > Symmetric layouts feel more predictable to users. Teams can over-optimize workflows and miss how people actually work.
- **Rule:** R-36.

### Staccato Drama

- **The pattern:** a run of short declarative fragments to manufacture a punchline: "It had no preference. No prior. No nostalgia."
- **Why it reads as AI:** one short sentence for emphasis is fine; a run of them sounds engineered. The rhythm is even, the effect is theatrical.
- **Before:**
  > Then the old rules were gone. No templates. No defaults. No safety.
- **After:**
  > The old rules no longer applied, and every page had to be designed from scratch.
- **Rule:** R-36.

### Theatrical Takeaways

- **The pattern:** dramatic single-line stage directions and conclusion-labeling: "Read that again.", "Let that sink in.", "The message is clear:", "That distinction matters.", "The takeaway is simple:", "Here is the bottom line:".
- **Why it reads as AI:** it tells readers how to react to an ordinary statement instead of letting the evidence carry weight.
- **Before:**
  > Automated rollbacks cut customer downtime by 40%. Read that again. Let that sink in.
- **After:**
  > Automated rollbacks cut customer downtime by 40%.
- **Rule:** R-36.

### Synonym Cycling

- **The pattern:** swapping synonyms to avoid repeating a word: "the protagonist faces a challenge, the main character must adapt, the central figure persists".
- **Why it reads as AI:** models rewrite to dodge repetition penalties. Human writers repeat the clearest word when it is clearest.
- **Before:**
  > The checkout is fast. The process is quick. The flow is speedy.
- **After:**
  > The checkout is fast. Everything happens in three clicks.
- **Rule:** R-36.

### False Ranges

- **The pattern:** "from X to Y" where X and Y are not on a meaningful scale: "from onboarding to scale", "from first click to final invoice, and everything in between".
- **Why it reads as AI:** the range is an impressive-sounding frame that covers nothing specific.
- **Before:**
  > From first touch to final invoice, and everything in between.
- **After:**
  > Handles quotes, invoices, and payment reminders.
- **Rule:** R-36.

### Monotonous Sentence Cadence (`6.7` — Low Burstiness)

- **The pattern:** four or more consecutive mid-length sentences (`8–16` words each) in the same paragraph whose lengths stay within a one-word spread.
- **Why it reads as AI:** scrubbing banned words while keeping every sentence the exact same length produces a flat, metronomic drone. Human prose has *burstiness*: a short, direct statement followed by a longer clause that carries the mechanism or exception.
- **Before:**
  > The billing engine processes every invoice at midnight each day. The webhook worker retries failed deliveries three times per hour. The audit ledger records every state transition in real time. The dashboard displays active subscriptions for every regional account team.
- **After:**
  > Invoices clear at midnight. If a webhook fails, the worker retries three times over the next hour while the audit ledger records every state transition for regional account teams.
- **Rule:** R-36, R-37 (`6.7` in `check_synthetic_markers.py`).

### Deferred Subject

- **The pattern:** withholding the real subject behind an empty setup clause and a colon: "It's the silent killer of productivity: context switching.", "There's one thing every founder misses: distribution."
- **Why it reads as AI:** stages an ordinary noun as a theatrical reveal.
- **Before:**
  > There's one thing slowing your releases down: manual QA.
- **After:**
  > Manual QA slows your releases down.
- **Rule:** R-02.
- **Not a ban:** introducing a real multi-item list ("There are three plans: Starter, Team, and Enterprise").

### Self-Answered Questions

- **The pattern:** asking a rhetorical question only to answer it immediately: "So what does this mean for you? It means...", "Why does this matter? Because...", "How does it work? Simple."
- **Why it reads as AI:** self-interviewing filler that adds zero information.
- **Before:**
  > Why does this matter? Because every minute of downtime costs you customers.
- **After:**
  > Every minute of downtime costs you customers.
- **Rule:** R-02.
- **Not a ban:** an FAQ entry or a real question asked by a user.

### Participial Tack-Ons

- **The pattern:** a trailing `-ing` clause appending unchecked praise or importance: "..., highlighting its commitment to quality.", "..., ensuring peace of mind.", "..., making it ideal for teams of any size." (`check_synthetic_markers.py` `1.3`).
- **Why it reads as AI:** bolts Significance Inflation onto the end of an ordinary fact.
- **Before:**
  > The app encrypts files before upload, ensuring your data stays safe and giving you peace of mind.
- **After:**
  > The app encrypts files before upload.
- **Rule:** R-16, R-36, C-5.
- **Not a ban:** a participle carrying a concrete fact ("the job runs nightly, starting at 02:00 UTC").

### Anaphora Stacks

- **The pattern:** three or more consecutive sentences repeating the same opening frame: "It's faster. It's cheaper. It's simpler."
- **Why it reads as AI:** mechanical cadence that usually pairs with Rule of Three Overuse and Staccato Drama.
- **Before:**
  > It syncs in real time. It works offline. It never loses a draft.
- **After:**
  > It syncs in real time, works offline, and saves every draft.
- **Rule:** R-02.
- **Not a ban:** an intentional speech, slogan, or user-supplied voice sample.

### Escalation Tails

- **The pattern:** infomercial transitions announcing another feature instead of stating it: "But that's not all.", "And that's just the beginning.", "And it gets better."
- **Why it reads as AI:** oversells a plain next point.
- **Before:**
  > It imports your contacts in one click. But that's not all: it also removes duplicates.
- **After:**
  > It imports your contacts in one click and removes duplicates.
- **Rule:** R-02.

### Mic-Drop Closers

- **The pattern:** ending paragraphs on a short quotable aphorism restating the point: "Because in the end, simplicity wins.", "And that changes everything."
- **Why it reads as AI:** repeats the same theatrical beat at the end of every paragraph without adding a fact.
- **Before:**
  > The new editor saves every keystroke locally. Because when it comes to your work, nothing should ever be lost.
- **After:**
  > The new editor saves every keystroke locally, so a crash loses nothing.
- **Rule:** R-02.
- **Not a ban:** a single deliberate tagline supplied by the user.

### Summary Echo

- **The pattern:** closing short copy with a restatement opener: "In summary,", "In conclusion,", "Overall,", "All in all,", "At the end of the day," (`check_synthetic_markers.py` `5.2`).
- **Why it reads as AI:** recaps a few paragraphs the reader just finished in vaguer words.
- **Before:**
  > Dark mode is live, exports run twice as fast, and SSO is on for every plan. All in all, this update makes the app faster, safer, and easier to use.
- **After:**
  > Dark mode is live, exports run twice as fast, and SSO is on for every plan.
- **Rule:** R-02.
- **Not a ban:** a closing summary on a long report that adds a concrete decision, owner, or date.

### Reflexive Concession

- **The pattern:** an empty balance clause naming no real condition: "While X has its merits,", "Of course, every situation is different.", "That said, there's no one-size-fits-all answer."
- **Why it reads as AI:** gestures at balance without specifying when the claim fails.
- **Before:**
  > While every team is different, most will benefit from weekly releases.
- **After:**
  > [Name the concrete exception if sourced, or state the claim plainly: "Most teams benefit from weekly releases."]
- **Rule:** R-02.

## Honesty & Evidence

### Fabricated Specifics

- **The pattern:** invented numbers, testimonials, names, dates, or features that look realistic but are not real.
- **Why it reads as AI:** a specific-looking fabrication is worse than a vague claim, because it reads as honest while being false. This is the one pattern that is a defect even when it sounds more human.
- **Before:**
  > Trusted by 10,000+ teams. "Acme cut our review time in half." - Sarah Chen, VP Engineering at [fictional company].
- **After:**
  > If no real customer exists, write no number and no quote. Say what the product does instead. Any real statistic needs a real source (R-17, R-36).
- **Rule:** R-17, R-18, R-36, R-38, C-5.

### Speculative Gap-Filling

- **The pattern:** when the writer does not know a fact, they write a sentence about not knowing it, then invent plausible filler: "the company was likely founded in the 1990s", "she maintains a low profile".
- **Why it reads as AI:** a guess dressed as fact. The model cannot find a source, so it papers over the gap.
- **Before:**
  > While specific details are limited, the founder likely started small and grew through word of mouth.
- **After:**
  > The founding details are not documented in our sources. (Or omit the sentence entirely. State a date only if a source provides one.)
- **Rule:** R-17, R-36.

### Generic Positive Conclusion

- **The pattern:** "The future looks bright", "Exciting times lie ahead", "This is a major step in the right direction".
- **Why it reads as AI:** an upbeat send-off that restates nothing and promises nothing. It pads the ending with optimism instead of information.
- **Before:**
  > The future looks bright for our customers as we continue our journey toward excellence.
- **After:**
  > (Cut the sentence. End on the last concrete fact, or state real plans if they exist.)
- **Rule:** R-36.

### Knowledge-Cutoff Disclaimers

- **The pattern:** training-cutoff caveats left inside deliverables: "As of my last update", "As of my knowledge cutoff", "I don't have access to real-time data" (`check_synthetic_markers.py` `4.2`).
- **Why it reads as AI:** chat-model leftover flagging an unverified fact.
- **Before:**
  > As of my last update, the API supports three regions.
- **After:**
  > [Verify with the user or source, then state plainly; omit unverified numbers (R-17).]
- **Rule:** R-02, R-17.

## Hygiene & Markdown

### Em Dashes

- **The pattern:** the em dash character (`—`) used as an aside or connector: *"institutions — not the people — continue"*.
- **Why it reads as AI:** it is one of the most reliable AI tells, and the core bans it outright.
- **Rule:** R-02 forbids the em dash in any text. Replace each one, in rough order of preference: a period (start a new sentence), a comma (a tight aside), a colon (introduce an explanation), parentheses (a true aside), or restructure the sentence. Also catch spaced em dashes (` — `) and double hyphens (` -- `) used the same way.
- **Before:**
  > The policy — announced without warning — affects thousands of workers.
- **After:**
  > The policy, announced without warning, affects thousands of workers.
- **Before:**
  > You don't say "Netherlands, Europe" as an address — yet this mislabeling continues.
- **After:**
  > You don't say "Netherlands, Europe" as an address, yet this mislabeling continues.
- **False positive:** many editors and journalists use em dashes deliberately. On its own an em dash is not proof of AI. It counts when it sits in a cluster with other tells (R-02 still bans it in output, but do not rewrite the user's deliberate style without saying so).
- **Voice sample:** if the user provides a writing sample that uses em dashes, that sample is a direction rather than agent copy. Surface it the way R-37 says (name the character, name the rule, ask), then match the sample's frequency only if the owner keeps it. Never keep or cut them silently.

### Boldface Overuse

- **The pattern:** every key term bolded mechanically: **"OKRs**, **KPIs**, **BMC**".
- **Why it reads as AI:** emphasis everywhere is emphasis nowhere. The page shouts at the reader.
- **Before:**
  > It blends **OKRs**, **KPIs**, and **visual strategy tools** for planning.
- **After:**
  > It blends OKRs, KPIs, and visual strategy tools for planning.
- **Rule:** R-36.
- **Carve-out:** the structural labels inside the `ui-refinery` rules themselves (the `**FORBIDDEN**` / `**REQUIRED**` markers in the `ui-refinery` core skill) are documentation conventions, not the mechanical bold-every-key-term pattern above, and are exempt.

### Excessive Quotation Marks

- **The pattern:** long text studded with quotation marks: quoting words that do not need quoting, scare quotes around ordinary terms, and quotes used as a default for emphasis or hedging. The page reads quoted rather than written.
- **Why it reads as AI:** models reach for quotation marks as a default way to add distance, irony, or emphasis without writing it into the sentence. Dense quoting is a reliable machine tell in longer text.
- **Before:**
  > The "solution" "streamlines" your "workflow" so you can "focus" on "what matters."
- **After:**
  > The solution streamlines your workflow so you can focus on what matters.
- **Rule:** R-36.
- **Not a ban:** dialogue, short stories, quoted real sources, and titles of works keep their quotes. The tell is quotes doing the work the sentence should do. One scare quote used once for a real reason is fine; a cluster of them is not. Minimize, do not strip quotes that carry meaning.

### Inline-Header Lists

- **The pattern:** list items that start with a bolded header followed by a colon: "- **User Experience:** The UX has been improved".
- **Why it reads as AI:** the header restates what the item already says. It is a formatting habit, not a structure.
- **Before:**
  > - **User Experience:** The interface is easier to use.
  > - **Performance:** Load times are faster.
  > - **Security:** Data is encrypted.
- **After:**
  > The update improves the interface, speeds up load times, and encrypts data in transit.
- **Rule:** R-36.
- **Carve-out:** the `- **Tell:**` / `- **Why:**` / `- **Fix:**` headers that structure every `ui-refinery` module entry are a documentation convention, not the header-restates-the-item habit above, and are exempt.

### Title Case in List Elements

- **The pattern:** capitalizing every word inside regular bullet lists or feature items: `- Comprehensive Security Audits Across All Repositories`.
- **Why it reads as AI:** sentence case reads faster and avoids mechanical template formatting; proper nouns, acronyms, and genuine titles keep their capitalization.
- **Rule:** R-36.

### Emojis in Headings

- **The pattern:** decoration emojis leading headings or bullets: 🚀 Launch, 💡 Key insight, ✅ Next steps.
- **Why it reads as AI:** the emoji carries no information. It decorates instead of communicating.
- **Before:**
  > 🚀 **Launch Phase:** The product ships in Q3
  > 💡 **Key Insight:** Users prefer simple pricing
- **After:**
  > The product ships in Q3. User research showed a preference for simple pricing.
- **Rule:** R-36.

### Filler Phrases

- **The pattern:** "In order to" for "to", "Due to the fact that" for "because", "At this point in time" for "now", "It is important to note that" for nothing.
- **Why it reads as AI:** filler inflates the sentence without adding meaning. It is padding a model adds to sound formal.
- **Before:**
  > In order to achieve this goal, it is important to note that we need more data.
- **After:**
  > To reach this goal, we need more data.
- **Rule:** R-36.

### Excessive Hedging

- **The pattern:** multiple qualifiers stacked on one claim: "could potentially possibly", "may perhaps".
- **Why it reads as AI:** hedging everywhere makes the text sound evasive. One qualifier does the work.
- **Before:**
  > This could potentially possibly be the reason the feature went unused.
- **After:**
  > This may be why the feature went unused.
- **Rule:** R-36.

### Colon-Reveal Headings

- **The pattern:** metaphor + colon + real topic: "The Silent Killer: Why Your Builds Are Slow", "Beyond the Dashboard: Rethinking Analytics".
- **Why it reads as AI:** stages a theatrical first half before labelling the section.
- **Before:**
  > ## The Silent Killer: Why Your Builds Are Slow
- **After:**
  > ## Why your builds are slow
- **Rule:** R-02.
- **Not a ban:** a product/plan label colon ("Starter: up to 5 repos") or a direct benefit/question heading.

### Template Section Names

- **The pattern:** sections named after essay scaffolding instead of content: "Introduction", "Overview", "Key Takeaways", "Final Thoughts", "Conclusion", "Wrapping Up".
- **Why it reads as AI:** generic template headings whose body usually echoes earlier paragraphs.
- **Before:**
  > ## Key Takeaways
- **After:**
  > (Cut the heading/recap, or place one concrete summary line at the top.)
- **Rule:** R-05.
- **Not a ban:** formats with fixed conventions (academic papers, READMEs, API references).

### Bullets for an Argument

- **The pattern:** chopping a causal reasoning chain ("because"/"so") into disconnected bullets.
- **Why it reads as AI:** bullets erase logical links to look visually tidy.
- **Before:**
  > - Users drop off at signup
  > - The form has twelve fields
  > - Shorter forms convert better
- **After:**
  > Users drop off at signup because the form asks for twelve fields. Shorter forms convert better, so cut the fields we do not need.
- **Rule:** R-05.
- **Not a ban:** ordered steps, options, specs, and checklists belong in lists.

### Exclamation Stacking

- **The pattern:** exclamation marks on multiple neutral statements in one paragraph: "Setup takes two minutes! You'll love the new dashboard!"
- **Why it reads as AI:** manufactures excitement across every line instead of reserving emphasis.
- **Before:**
  > We've shipped dark mode! It's live for everyone today! Try it out!
- **After:**
  > Dark mode is live for everyone today.
- **Rule:** R-02.
- **Not a ban:** one exclamation in a genuinely excited voice or dialogue.

### Line-Per-Sentence Posts

- **The pattern:** social-post template with every sentence on its own line, a blank-line hook, "Here's what I learned:", a numbered list, an "Agree?" closer, and a wall of hashtags.
- **Why it reads as AI:** mechanical growth-poster frame reused regardless of content.
- **Before:**
  > We rewrote onboarding.
  >
  > It changed everything.
  >
  > Agree? #saas #growth
- **After:**
  > We rewrote onboarding and cut the signup form to three fields. Has anyone seen the opposite? #onboarding
- **Rule:** R-02, R-05.
- **Not a ban:** a single isolated line for emphasis or a user-supplied posting style sample.

## Turkish Synthetic Markers (`TR-1` to `TR-7`)

When authoring or reviewing Turkish copy, product UI strings, or technical documentation (`--lang tr` or `--lang auto`), apply the same de-AI prose discipline to machine-translated calques and Turkish brochure tropes:

### `TR-1`: Turkish Negative Parallelism (`Sadece X değil, aynı zamanda Y`)

- **The pattern:** `sadece/yalnızca X değil, aynı zamanda Y`, `bir X olmaktan öte`, or `X değil, bir Y'dir` used to manufacture depth.
- **Why it reads as AI:** direct calque of English `It's not just X, it's Y`. Natural Turkish states what the thing is without staging a contrast nobody asked for.
- **Before:**
  > Bu uygulama sadece bir görev yöneticisi değil, aynı zamanda ekip kültürünüzün yeni yaşam tarzıdır.
- **After:**
  > Bu uygulama ekibinizin günlük görevlerini ve teslim tarihlerini tek ekranda toplar.
- **Rule:** R-36.

### `TR-2`: Turkish Inflated Significance (`Kritik bir rol oynamaktadır`)

- **The pattern:** `kritik/hayati/kilit bir rol oynamaktadır`, `adeta bir ... niteliğindedir`, `devrim niteliğinde`, `dönüm noktası niteliğindedir`, `yeni bir çağ başlatmaktadır`, `mihenk taşı`, `ev sahipliği yapmaktadır`.
- **Why it reads as AI:** ceremonious significance claims and formal `-mektedir/-maktadır` padding where a direct verb (`vardır`, `içerir`, `azaltır`) belongs.
- **Before:**
  > Önbellek katmanımız sistem performansında kritik bir rol oynamaktadır ve devrim niteliğinde bir hız sunar.
- **After:**
  > Önbellek katmanı veritabanı sorgu süresini 120 milisaniyeden 15 milisaniyeye düşürür.
- **Rule:** R-16, R-36.

### `TR-3`: Turkish Brochure Vocabulary & English Calques (`Bir üst seviyeye taşıyın`)

- **The pattern:** `bir üst seviyeye taşıyın`, `potansiyelinizi ortaya çıkarın`, `kusursuz bir deneyim`, `kusursuz bir şekilde`, `dinamik dünyasında`, `geniş bir yelpazede`, `bütüncül bir yaklaşım`, `uçtan uca çözüm`, `kalbinde yer alan`, `kapılarını aralamaktadır`, `harmoni`, `serüven`.
- **Why it reads as AI:** literal translations of English software buzzwords (`take to the next level`, `unlock your potential`, `seamlessly`, `in the dynamic world of`).
- **Before:**
  > İş akışınızı bir üst seviyeye taşıyın ve ekibinizin potansiyelini kusursuz bir şekilde ortaya çıkarın.
- **After:**
  > Tekrarlayan onay adımlarını otomatikleştirerek haftalık rapor süresini kısaltın.
- **Rule:** R-16, R-36.

### `TR-4`: Trailing Converb Commentary (`..., önemini vurgulayarak`)

- **The pattern:** tacking a trailing `-erek/-arak` clause onto the end of a sentence (`..., önemini vurgulayarak`, `..., deneyim sunarak`, `..., katkı sağlayarak`, `..., gözler önüne sererek`).
- **Why it reads as AI:** mirrors the English trailing `-ing` participle clause (`..., highlighting its importance`). Turkish syntax places adverbial `-erek/-arak` clauses before the main verb, never as a tacked-on summary at the end.
- **Before:**
  > Sistem her gün binlerce işlemi doğruluyor, güvenliğin önemini vurgulayarak.
- **After:**
  > Sistem her gün binlerce işlemi doğruluyor.
- **Rule:** R-16, R-36.

### `TR-5`: Didactic Filler & Summary Openers (`Unutmamak gerekir ki`, `Sonuç olarak`)

- **The pattern:** `Unutmamak/Belirtmek/Vurgulamak gerekir ki`, `İlk olarak belirtmek gerekir ki`, `Şunu da unutmamak gerekir ki`, `Günün sonunda`, and paragraph openers like `Sonuç olarak,`, `Özetle,`, `Genel olarak değerlendirildiğinde,`.
- **Why it reads as AI:** throat-clearing before an ordinary statement or a formulaic essay conclusion.
- **Before:**
  > Unutmamak gerekir ki yedekleme işlemi zaman alır. Sonuç olarak, planlama şarttır.
- **After:**
  > Yedekleme işlemi veri boyutuna göre 10 ila 30 dakika sürer; bakım penceresini buna göre seçin.
- **Rule:** R-36.

### `TR-6`: Turkish Chatbot Leftovers (`Umarım bu yardımcı olur`)

- **The pattern:** `Umarım bu yardımcı olur`, `Başka bir sorunuz olursa`, `Harika bir soru`, `İşte ... hakkında bilmeniz gerekenler`.
- **Why it reads as AI:** conversational assistant wrappers left inside deliverables or documentation.
- **Before:**
  > İşte kurulum adımları hakkında bilmeniz gerekenler. Umarım bu yardımcı olur!
- **After:**
  > Kurulum için aşağıdaki üç komutu sırayla çalıştırın.
- **Rule:** R-36.

### `TR-7`: Turkish Bureaucratic Passive & Rhetorical Bridges (`olanak tanımaktadır`, `İşte tam bu noktada`)

- **The pattern:** bureaucratic `-mektedir/-maktadır` verb padding (`olanak tanımaktadır`, `imkân sağlamaktadır`, `gerçekleştirilmektedir`) and synthetic rhetorical bridges (`Peki, bu neden önemli?`, `Peki bu ne anlama geliyor?`, `İşte tam da bu noktada`).
- **Why it reads as AI:** models default to stiff institutional passives (`olanak tanımaktadır` instead of `sağlar` or direct active verbs) and translate English blog signposting (`So why does this matter?`, `That's where X comes in`) word for word.
- **Before:**
  > Peki, bu neden önemli? İşte tam da bu noktada yeni doğrulama motorumuz devreye girerek hataları önlemeye olanak tanımaktadır.
- **After:**
  > Yeni doğrulama motoru şema hatalarını derleme aşamasında yakalar.
- **Rule:** R-02, R-16, R-36.

## What NOT to flag

A clean human writer can hit several patterns above without any AI involvement. Before editing, sanity-check that you are not gutting legitimate prose. These are **not** reliable indicators on their own:

- **Perfect grammar and consistent style.** Many writers are professionals or have been edited. Polish does not equal AI.
- **Mixed casual and formal registers.** This often signals a real person, not a chatbot.
- **"Bland" or "robotic" prose.** AI prose has specific tells. Generic dryness without those tells is just dry writing.
- **Formal vocabulary.** AI overuses *specific* words (see Empty AI Vocabulary), not all fancy words. Do not flatten a precise word just because it sounds brainy.
- **Common transition words in isolation.** One "however" or "additionally" is not a tell. They count only when piled up.
- **Curly quotes alone.** macOS, Word, and most CMSes auto-curl by default. Curly quotes count only when stacked with other tells.
- **Em dashes alone.** Editors and journalists use them. An em dash is evidence only inside a cluster.
- **One short emphatic sentence.** Humans use clipped sentences to land a point. Flag staccato drama only when several fragments appear in a row.
- **Unsourced claims.** Most of the web is unsourced. Lack of citations proves nothing.
- **Secondhand text.** Do not rewrite phrases inside quotations, titles, proper names, or examples where the phrase is being discussed rather than used.

**Look for clusters, not isolated tells.** A single em dash means nothing. Em dashes plus rule of three plus "vibrant tapestry" plus a generic conclusion is a confession. This matches the core's own guidance: Part 1 is a diagnostic scan, not a ban list.

## Signs of human writing (preserve these)

Lean toward leaving the prose alone when you see these. They are evidence of a real person, and over-editing destroys what makes the copy sound human:

- **Specific, unusual, hard-to-fabricate detail.** A real address. A weird quote. LLMs round off specifics; humans hoard them.
- **Mixed feelings and unresolved tension.** "I think this is mostly good, but it bothers me." LLMs default to clean takes.
- **Dated, era-bound references.** Slang, memes, or in-jokes that map to a specific year and subculture.
- **Variety in sentence length.** Real writing alternates short and long. AI writing tends toward an even, mid-length cadence.
- **Genuine asides and self-corrections.** "(I keep wanting to say 'almost' here, but it really was certain.)"

## Voice calibration (optional)

If the user provides a sample of their own writing, match it before rewriting:

1. Read the sample first. Note its sentence lengths, vocabulary, paragraph openings, punctuation, and recurring phrases.
2. Match those habits instead of merely deleting AI patterns. Do not upgrade casual words or regularize deliberate quirks.
3. The sample outranks this skill's style rules, except where R-02/R-16 apply. R-02 and R-16 govern copy the agent authors; a sample that uses em dashes is a direction, so it goes through R-37's conflict protocol, and you match its frequency only if the owner keeps it. R-02 and R-16 apply in full to any copy the user did not authorize.

Without a sample, use the defaults above and calibrate to the active `DESIGN.md` domain archetype (`MODE: UTILITY`, `MODE: EDITORIAL`, or `MODE: GAME & INTERACTIVE`). Matching the author beats scrubbing the tell.

### Domain Archetype Voice Examples (`UTILITY`, `EDITORIAL`, `GAME & INTERACTIVE`)

When no user sample is provided, never fall back to a flat textbook monotone. Anchor sentence cadence and word choice to the active domain archetype:

- **`MODE: UTILITY` (Engineering / Operations):** Crisp, metric-first, zero throat-clearing. Pair a short status declaration with the exact operational threshold.
  > Quotas reset at 00:00 UTC. Any worker exceeding 500 requests per minute receives an HTTP 429 with a `Retry-After` header.
- **`MODE: EDITORIAL` (Product / Publication):** High burstiness, concrete nouns, unapologetic point of view. Open with a sharp observation, then unpack the mechanism in a longer sentence.
  > Most changelogs lie by omission. They list the three features marketing wanted on the banner and bury the breaking schema change in a footnote six scrolls down.
- **`MODE: GAME & INTERACTIVE` (Diegetic / World-Bound):** Tactile verbs, diegetic nouns (hull integrity, signal lock, stamina burn, ammo reserve), and immediate consequence. Never use SaaS brochure language (`seamless experience`, `unlock your potential`) inside game UI or lore.
  > Reactor coolant is venting into Sector 4. Seal the bulkhead now and you lose the cargo bay; wait thirty seconds and you lose the ship.

## Draft, audit, final

Run this loop before delivering copy:

1. **Draft.** Rewrite the text applying the patterns above. Check that it reads naturally aloud, varies sentence length, prefers specific detail and simple constructions, and keeps the appropriate register.
2. **Audit.** Ask two questions and answer them briefly: "What makes this obviously AI generated?" and "Does it state any fact, name, number, date, or citation that is not in the source?" A fabrication is a defect even when it sounds more human than the vague original.
3. **Final.** Revise to address both answers. Check for unapproved em-dash clusters and banned buzzwords one last time (R-02, R-16). A hit means the draft is not done.

## Deterministic scan (local addition)

When you can run code, measure before and after rewriting with the bundled scanner (Python standard library only):

```bash
plumb-guard synthetic-markers draft.md              # portable CLI (cwd-independent)
plumb-guard synthetic-markers draft.md --summary    # counts and density per 1,000 words
plumb-guard synthetic-markers - --json < draft.md   # machine-readable, reads stdin
# Canonical installed fallback (when plumb-guard is not on PATH):
python3 ~/.gemini/config/skills/ui-refinery/scripts/check_synthetic_markers.py draft.md
```

* `--source agent` (default) applies R-02/R-16 strictly: every unapproved em dash in copy you wrote is a finding. Use `--source human` for text the user supplied; em dashes are then flagged only in clusters, and per R-37 you surface them instead of rewriting them silently.
* `--profile technical` switches off the Markdown-structure signs (Title Case headings, bold label bullets, small tables, emoji headings) that are normal in engineering docs; content, filler and chat-leftover signs stay on. `--lang tr` (or `auto`) adds the Turkish signs.
* The scanner catches pattern-level signs only; rhythm, elegant variation and puffed-up structure still need the read-aloud pass. A hit you keep on purpose (a quotation, a proper noun, a literal use) is fine: mention it.
* Rewriting changes how things are said, never what is said: keep every fact, number, name, date, link and quotation, and leave clean sentences alone. Report the finding counts before → after.

## Copywriting Skill Checklist

Run these alongside the core Delivery Gate when the task is copy work. Every line below must be true:

- [ ] No fabricated numbers, testimonials, names, dates, or claims; everything real or a labeled placeholder (R-17, R-18, R-36, R-38)
- [ ] Buzzwords from R-02 / R-16 and the Empty AI Vocabulary list replaced with specific, evidenced language
- [ ] No unapproved em dashes in the output (R-02, R-16); if the user's own sample voice uses them, they were surfaced under R-37 and the owner kept them
- [ ] No excessive quotation marks: quotes only where they carry meaning (dialogue, real citations, titles), not as default emphasis (R-36)
- [ ] No all-caps emphasis clauses: emphasis written into the sentence, not shouted with caps (R-36)
- [ ] Every sentence names its actor: no actorless passive, no abstraction given a human verb, where a real subject was available (R-16)
- [ ] CTAs specific to the action, not generic templates (R-15)
- [ ] No AI-rhythm tells: no forced rule of three, no negative parallelism, no staccato drama, no theatrical takeaways, no aphorism formulas, no false ranges (R-36)
- [ ] No manufactured suspense: no deferred subjects, teaser reveals ("The result?"), self-answered questions, or scene-setting hypotheticals in place of a real example (R-02, R-16)
- [ ] No participial tack-ons adding unchecked praise/importance at sentence ends, and no mic-drop closers or summary echoes (R-02, R-36, C-5)
- [ ] No chatbot openers, faux-intimate reader address, audience sweeps, straw-man setups, reflexive concessions, or knowledge-cutoff disclaimers (R-02, R-16, R-36)
- [ ] No keynote cadence: no anaphora stacks, escalation tails ("But that's not all"), or exclamation marks stacked on neutral statements (R-02)
- [ ] Plain verbs and real quantities: no copula avoidance ("serves as", "boasts"), nominalized verbs, or vague quantifiers ("a myriad of") (R-02, R-16, R-17)
- [ ] Headings label content: no colon-reveal titles, no template essay headings ("Key Takeaways", "Final Thoughts"), arguments written as prose rather than bullets, no line-per-sentence social templates (R-02, R-05)
- [ ] No temporal runway clichés padding section openings and regular bullet items use natural sentence case rather than mechanical title case (R-16, R-36)
- [ ] Voice present: the copy has a real voice (the user's sample or a clearly chosen tone), not a sterile default (R-37)
- [ ] Read aloud: the copy sounds like a person wrote it, not like a model padded it
