import type {ReactNode} from 'react';
import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

type FeatureItem = {
  title: string;
  Svg: React.ComponentType<React.ComponentProps<'svg'>>;
  description: ReactNode;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'HackTheBox',
    Svg: require('@site/static/img/htb.svg').default,
    description: (
      <>
        HackTheBox 靶机的渗透测试笔记，包含详细的攻击步骤和技术分析。
      </>
    ),
  },
  {
    title: 'VulnHub',
    Svg: require('@site/static/img/htb.svg').default,
    description: (
      <>
        VulnHub 靶机的完整 Walkthrough，记录从信息收集到权限提升的全过程。
      </>
    ),
  },
  {
    title: '持续更新',
    Svg: require('@site/static/img/htb.svg').default,
    description: (
      <>
        不断学习新的渗透测试技术，持续更新笔记内容。
      </>
    ),
  },
];

function Feature({title, Svg, description}: FeatureItem) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): ReactNode {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
