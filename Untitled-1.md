Who is the primary user for this build?

A web tester, BLANCHE should find old libraries, search files for new urls and match on interesting terms.

What should happen in the first ten seconds after opening BLANCHE?

Should be two buttons, run search with its advanced search patterns. Then view documents.

Which existing surfaces are core enough to remain in primary navigation?

Specifically: Feed, Search, Document Center, Latent Features, Interest Model, and Engagement Profiles. My inclination is to keep Search, Findings, and task status prominent; place Interest Model, profiles, modules, exports, and logs under Labs or Settings.

This is correct. Place under labs

How automatic should BLANCHE be?

Automatic. The scoring engine promotes whether or not blanche pops up a window to ask the user a question. The questions should drive testing and be based off a discovered artifact or set of terms its looking for.

What should constitute a completed search task?

If its stuck on anti-automation do not call it complete, give the user a copy and pastable search string for that window they can hit a button and copy to clipboard.

If the search runs, its complete. Many of our searches wont return results.

Also throttle recurring searches on the same engine with a configurable setting in settings, default is 300ms.

What information must a regular tester never have to see?

The labs section can contain the nerdy stuff. What a tester needs to see is:

* Oh a search returned results.
* This version of jquery is so old the pixels have mold, ill report that.
* The archival site seems different from the main one, why?
* The webpacked javascript has a ton of hashmaps its not turning on, lets see if we can deobfuscate and add those features.

They need the output of the automation, if a button doesnt work, create an error log, and we will deal with that.

OH finally. The autodownloader needs some work. It startles a tester when there are 50 files downloaded when they go to a website. Maybe we need a better method, maybe we can create a queue and rules for them based on interesting keywords.

By 300 ms, do you mean spacing between consecutive searches on the same engine, or a cooldown before BLANCHE may repeat the same query later? I currently interpret it as launch spacing.

both at 300ms is fine default

May BLANCHE read the rendered search-results page in the tabs it opens, extract result links, deduplicate them, and then close or background those tabs? Without this, it cannot reliably say “search returned results.”

Yes

For documents, may BLANCHE automatically fetch the body into memory for keyword/URL analysis while defaulting filesystem download to off? That preserves useful automation without filling Downloads.

yes

How should questions interrupt the tester?
My recommendation is a question card in the side panel plus a badge; only very high-scoring findings open a separate window or notification.

question card side panel

For “old library,” is identifying the library and shipped version enough, or should BLANCHE also consult public release/vulnerability data and report age, latest known version, and associated advisories?

you can use something like snyk.io to see if the libraries are old and vulnerable for now

Should the default search recipe include all of these?

It