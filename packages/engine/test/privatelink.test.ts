import { describe, expect, it } from 'vitest';
import { fullAccessPolicy } from '../src/index.js';

const doc = (st: object) => JSON.stringify({ Version: '2012-10-17', Statement: [st] });

describe('fullAccessPolicy', () => {
  it('finds the default endpoint policy and its spellings', () => {
    expect(fullAccessPolicy(doc({ Effect: 'Allow', Principal: '*', Action: '*', Resource: '*' }))).toBe(true);
    expect(fullAccessPolicy(doc({ Effect: 'Allow', Principal: { AWS: '*' }, Action: ['s3:*'], Resource: ['*'] }))).toBe(true);
    expect(fullAccessPolicy(JSON.stringify({ Statement: { Effect: 'Allow', Principal: '*', Action: 'dynamodb:*', Resource: '*' } }))).toBe(true);
  });

  it('does not count restricted statements', () => {
    expect(fullAccessPolicy(doc({ Effect: 'Allow', Principal: '*', Action: '*', Resource: '*', Condition: { StringEquals: { 'aws:ResourceOrgID': 'o-1' } } }))).toBe(false);
    expect(fullAccessPolicy(doc({ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: '*' }))).toBe(false);
    expect(fullAccessPolicy(doc({ Effect: 'Allow', Principal: '*', Action: '*', Resource: 'arn:aws:s3:::mine/*' }))).toBe(false);
    expect(fullAccessPolicy(doc({ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::111122223333:root' }, Action: '*', Resource: '*' }))).toBe(false);
    expect(fullAccessPolicy(doc({ Effect: 'Allow', Principal: '*', NotAction: 's3:DeleteObject', Resource: '*' }))).toBe(false);
    expect(fullAccessPolicy(doc({ Effect: 'Deny', Principal: '*', Action: '*', Resource: '*' }))).toBe(false);
  });

  it('says it cannot tell when the policy is not JSON', () => {
    expect(fullAccessPolicy('not json')).toBeUndefined();
  });
});
