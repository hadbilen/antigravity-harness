import { useRef } from "react";
import { motion, useScroll, useTransform } from "motion/react";
import { cls } from "./utils";

/* Reading word-fill: a long paragraph where each word brightens as it passes
   through the reading zone. The whole effect is one scroll progress value sliced
   into n equal windows — word i owns [i/n, (i+1)/n] and rides 0.15 -> 1 opacity.
   Offset ["start 0.8", "start 0.2"] puts the fill in the comfortable middle of
   the viewport rather than at the edges. */

const DIM = 0.15;

type AboutTextFillProps = {
  /** Small label above the paragraph. */
  tag?: string;
  /** The paragraph. Split on whitespace; every word animates. */
  text: string;
  /** Anything you want under the text — your own buttons, links, nothing. */
  actions?: React.ReactNode;
  className?: string;
};

const AboutTextFill = ({ tag, text, actions, className }: AboutTextFillProps) => {
  const ref = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ["start 0.8", "start 0.2"],
  });

  const words = text.trim().split(/\s+/);

  return (
    <section
      ref={ref}
      data-section="about"
      className={cls("w-content-width mx-auto py-24 md:py-32", className)}
    >
      {tag ? (
        <p className="text-sm uppercase tracking-widest opacity-60 mb-8">{tag}</p>
      ) : null}

      <p className="text-3xl md:text-5xl leading-tight font-medium flex flex-wrap gap-x-[0.25em]">
        {words.map((word, i) => (
          <Word
            key={`${word}-${i}`}
            word={word}
            progress={scrollYProgress}
            range={[i / words.length, (i + 1) / words.length]}
          />
        ))}
      </p>

      {actions ? <div className="mt-12 flex flex-wrap gap-4">{actions}</div> : null}
    </section>
  );
};

const Word = ({
  word,
  progress,
  range,
}: {
  word: string;
  progress: ReturnType<typeof useScroll>["scrollYProgress"];
  range: [number, number];
}) => {
  const opacity = useTransform(progress, range, [DIM, 1]);
  return <motion.span style={{ opacity }}>{word}</motion.span>;
};

export default AboutTextFill;
