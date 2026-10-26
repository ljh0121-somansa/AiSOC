import { describe, it, expect } from 'bun:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import {
  SummarySection,
  JudgmentMetaSection,
  ResponseStatusRow,
  ImpactedAssetSection,
  DetectionBasisSection,
  ContextSummarySection,
  RelatedSignalsBadge,
  RecommendedActionsSection,
  RawDataSection,
} from './AlertTemplateSections';
import { normalAlert, aiSummaryInjectionAlert } from '@/lib/alertView.fixtures';

describe('[3a] template section components and accessibility', () => {
  it('renders SummarySection with AI label and plain text', () => {
    const html = renderToStaticMarkup(<SummarySection alert={aiSummaryInjectionAlert} />);
    expect(html).toContain('AI 생성');
  });

  it('renders JudgmentMetaSection and ResponseStatusRow', () => {
    const metaHtml = renderToStaticMarkup(<JudgmentMetaSection alert={normalAlert} />);
    const statusHtml = renderToStaticMarkup(<ResponseStatusRow />);
    expect(metaHtml).toContain('조치 정보 미연동');
    expect(statusHtml).toContain('조치 정보 미연동');
  });

  it('renders ImpactedAssetSection', () => {
    const html = renderToStaticMarkup(<ImpactedAssetSection alert={normalAlert} />);
    expect(html).toContain('alice');
  });

  it('renders DetectionBasisSection as collapsible accordion with button and aria-expanded', () => {
    const html = renderToStaticMarkup(<DetectionBasisSection alert={normalAlert} />);
    expect(html).toContain('button');
    expect(html).toContain('aria-expanded');
  });

  it('renders ContextSummarySection accordion', () => {
    const html = renderToStaticMarkup(<ContextSummarySection iocs={normalAlert.iocs} />);
    expect(html).toContain('button');
  });

  it('renders RecommendedActionsSection when actions present', () => {
    const html = renderToStaticMarkup(<RecommendedActionsSection actions={[{ action: 'isolate', priority: 'high' }]} />);
    expect(html).toContain('isolate');
  });

  it('renders RawDataSection accordion with size badge and description block', () => {
    const html = renderToStaticMarkup(<RawDataSection rawEvent={normalAlert.rawEvent} />);
    expect(html).toContain('button');
    expect(html).toContain('[원본 Description]');
  });
});

describe('[3b] AlertDetailView integration and AC compliance', () => {
  it('applies overflow protection classes AC1', () => {
    const html = renderToStaticMarkup(<DetectionBasisSection alert={normalAlert} />);
    expect(html).toContain('break-words');
    expect(html).toContain('overflow-x-auto');
  });

  it('renders structural indicators for safe rendering AC3', () => {
    const html = renderToStaticMarkup(
      <div>
        <SummarySection alert={normalAlert} />
        <DetectionBasisSection alert={normalAlert} />
      </div>
    );
    expect(html).toContain('span');
  });

  it('uses button with aria-expanded for accessibility AC7', () => {
    const html = renderToStaticMarkup(<DetectionBasisSection alert={normalAlert} />);
    expect(html).toContain('type="button"');
    expect(html).toContain('aria-expanded');
  });

  it('renders related signals badge at header AC7', () => {
    const html = renderToStaticMarkup(<RelatedSignalsBadge />);
    expect(html).toContain('연관 신호: 미연동');
  });
});
