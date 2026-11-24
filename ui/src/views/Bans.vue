<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("bans.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <p class="mg-bottom-md">{{ $t("c.bansHelp") }}</p>
      </cv-column>
    </cv-row>
    <cv-row v-if="error">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('c.error')"
          :description="error"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <cv-row class="toolbar">
      <cv-column>
        <NsButton
          type="button"
          kind="secondary"
          :icon="Unlocked20"
          :disabled="busy || !selected.length"
          @click="unban"
          >{{ $t("c.unban") }} ({{ selected.length }})</NsButton
        >
        <NsButton
          type="button"
          kind="ghost"
          :disabled="busy || !visible.length"
          @click="selectAll(!allSelected)"
          >{{ $t("c.selectAll") }}</NsButton
        >
        <NsButton
          type="button"
          kind="ghost"
          :icon="Renew20"
          :disabled="busy"
          @click="load"
          >{{ $t("c.refresh") }}</NsButton
        >
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <cv-search
          v-model="search"
          :label="$t('c.search')"
          :placeholder="$t('c.search')"
          :clear-aria-label="$t('c.clearSearch')"
          class="mg-bottom-md"
        />
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <cv-tile v-if="!decisions.length && !busy" light>
          <NsEmptyState :title="$t('c.noBans')" />
        </cv-tile>
        <cv-data-table v-else :columns="columns" :zebra="false">
          <template slot="data">
            <cv-data-table-row v-for="d in visible" :key="d.id" :value="d.ip">
              <cv-data-table-cell>
                <cv-checkbox
                  :aria-label="d.ip"
                  :label="d.ip"
                  hide-label
                  :value="d.ip"
                  :checked="selected.includes(d.ip)"
                  @change="toggle(d.ip, $event)"
                />
              </cv-data-table-cell>
              <cv-data-table-cell>
                <code>{{ d.ip }}</code>
              </cv-data-table-cell>
              <cv-data-table-cell>{{ d.scenario }}</cv-data-table-cell>
              <cv-data-table-cell>{{
                d.machine || d.origin
              }}</cv-data-table-cell>
              <cv-data-table-cell>{{ d.country || "—" }}</cv-data-table-cell>
              <cv-data-table-cell>{{
                d.duration || d.until
              }}</cv-data-table-cell>
            </cv-data-table-row>
          </template>
        </cv-data-table>
      </cv-column>
    </cv-row>
  </cv-grid>
</template>
<script>
import task from "../task";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import Unlocked20 from "@carbon/icons-vue/es/unlocked/20";
export default {
  name: "Bans",
  mixins: [task],
  data: () => ({
    busy: false,
    error: "",
    decisions: [],
    selected: [],
    search: "",
    Renew20,
    Unlocked20,
  }),
  computed: {
    columns() {
      return [
        "",
        "IP",
        this.$t("c.reason"),
        this.$t("c.detectedBy"),
        this.$t("c.country"),
        this.$t("c.remaining"),
      ];
    },
    visible() {
      const q = this.search.trim().toLowerCase();
      return q
        ? this.decisions.filter((d) =>
            (d.ip + " " + d.scenario + " " + d.machine)
              .toLowerCase()
              .includes(q)
          )
        : this.decisions;
    },
    allSelected() {
      return (
        this.visible.length > 0 &&
        this.visible.every((d) => this.selected.includes(d.ip))
      );
    },
  },
  created() {
    this.load();
  },
  methods: {
    toggle(ip, on) {
      this.selected = on
        ? [...new Set([...this.selected, ip])]
        : this.selected.filter((x) => x !== ip);
    },
    selectAll(on) {
      this.selected = on ? [...new Set(this.visible.map((d) => d.ip))] : [];
    },
    async load() {
      this.busy = true;
      try {
        this.error = "";
        this.decisions = (await this.task("list-decisions")).decisions || [];
        const present = new Set(this.decisions.map((d) => d.ip));
        this.selected = this.selected.filter((ip) => present.has(ip));
      } catch (e) {
        this.error = e.message;
      } finally {
        this.busy = false;
      }
    },
    async unban() {
      this.busy = true;
      try {
        await this.task("unban", { addresses: this.selected });
        this.selected = [];
        await this.load();
      } catch (e) {
        this.error = e.message;
      } finally {
        this.busy = false;
      }
    },
  },
};
</script>
