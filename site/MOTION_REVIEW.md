# Landing-page motion and interface review

Scope: the landing page, explanatory SVGs, report previews, and shared copy, disclosure, and search interactions. The original fonts, palette, installation commands, and destinations remain.

## Findings and changes

| Before                                          | After                                                                       | Why                                                                         |
| ----------------------------------------------- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Paper-stack hero and repeated section entrances | Simple static hero; entrances removed                                       | Keep attention on the explanation.                                          |
| Three workflow text tiles                       | One continuous, three-stage isometric sequence                              | Explain files → inspection → human review.                                  |
| Repeated anatomy arrow buttons                  | No buttons; decorative mechanisms respond to fine-pointer hover             | Remove unnecessary controls and tab stops. All explanations remain visible. |
| Encoded text without a clear explanation        | Static encoded/decoded example with plain-language context                  | Explain what the code hides before adding motion.                           |
| Entire report text morphing                     | Terminal types its command and prints rows; keyboard selection is immediate | Use the terminal metaphor only where it helps.                              |
| FAQ height animation                            | Immediate disclosure state with a short pointer-open content entrance       | Avoid layout animation and delayed closing.                                 |

Implementation references: `src/scripts/workflow-animation.js:11`, `src/scripts/bento-anatomy.js:44`, `src/scripts/terminal-preview.js:23`, and `src/scripts/interactions.js:183`.

## Interface coverage

- **Accessibility:** native tabs, roving tab stops, arrow/Home/End keys, visible focus, reduced motion, and one accessible copy of report text. Decorative SVGs and the animated terminal copy are hidden from the accessibility tree.
- **Layout:** a prominent hero, quieter workflow introduction, compact split coverage heading, varied bento proportions, reversed trust composition, report heading and selector integrated into the demo, and a compact coverage-limits strip. Narrow layouts reflow.
- **Writing:** the decoded example explains a hidden network request and states that encoding alone does not prove malicious intent. Illustrations and abbreviated reports are labeled as examples.
- **Typography:** original system UI and monospace fonts retained; simpler headings and readable line lengths.
- **Color:** original porcelain, graphite, and vermilion palette retained. Dark-card supporting text uses a lighter gray. Light and dark OS preferences retain the intentional palette; this does not introduce a separate dark theme.
- **UI and motion:** shared 150/250 ms interaction tokens, 40 ms terminal-row cadence, fine-pointer hover gating, and no generation skeletons. The nine-second workflow is an explanatory loop requested in the brief, not an interaction delay.

## Verification

- Desktop 1440px, phone 390px, and 320px with 200% root text size: no document-level horizontal overflow.
- Live keyboard checks passed for report tabs, installation tabs, and FAQ. Terminal keyboard selection displays the complete output immediately.
- Seven workflow animations run while visible; zero run after scrolling away. Reduced motion produces zero running animations. Terminal completes and stops. Console clean.
- Artwork audit: zero floating ends among 196 audited endpoints. Desktop and phone screenshots inspected.
- Formatting, build, and documentation checks passed: 16 routes, 255 search destinations, six artifacts. Astro check: zero errors, zero warnings, one existing deprecated clipboard-fallback hint.

## Verdict

**Approve for the requested motion scope.** The workflow intentionally continues while visible, as requested; reduced motion keeps it still. This covers the tested interactions and layouts, not a full assistive-technology certification.
