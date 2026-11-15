/** Crown jewel tags: shared by attack chain ranking and the minimum cut. */
import type { Eni, NetworkModel } from './types.js';

const JEWEL_TAGS = ['pinhole:crown-jewel', 'crown-jewel', 'crownjewel'];
const CLASS_TAGS = ['data-classification', 'dataclassification', 'classification', 'data_classification'];
const SENSITIVE = /^(confidential|restricted|secret|top-?secret|sensitive|pii|phi|pci|critical)$/i;

/** Why an interface is a crown jewel by its tags (instance, then subnet, then VPC), or undefined. */
export function jewelTag(model: NetworkModel, e: Eni): string | undefined {
  const sources = [e.instanceId ? model.instances.get(e.instanceId)?.tags : undefined, model.subnets.get(e.subnetId)?.tags, model.vpcs.get(e.vpcId)?.tags];
  for (const tags of sources) {
    for (const [k, v] of Object.entries(tags ?? {})) {
      const key = k.toLowerCase();
      if (JEWEL_TAGS.includes(key) && !/^(false|no|0)$/i.test(v)) return `tagged ${k}=${v}`;
      if (CLASS_TAGS.includes(key) && SENSITIVE.test(v.trim())) return `tagged ${k}=${v}`;
    }
  }
  return undefined;
}
