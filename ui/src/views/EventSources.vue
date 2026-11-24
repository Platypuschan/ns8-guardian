<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("eventSources.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <p class="mg-bottom-md">{{ $t("c.eventSourcesHelp") }}</p>
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
    <cv-row>
      <cv-column class="page-subtitle">
        <h4>{{ $t("c.addEventSource") }}</h4>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <cv-tile light>
          <cv-form @submit.prevent>
            <cv-text-input
              v-model="name"
              :label="$t('c.name')"
              :helper-text="$t('c.memberNameHelp')"
              :invalid-message="fieldError('name')"
              :disabled="busy"
              class="mg-bottom-md"
            />
            <cv-text-input
              v-model="module"
              :label="$t('c.moduleIdentity')"
              :helper-text="$t('c.moduleIdentityHelp')"
              :invalid-message="fieldError('module')"
              :disabled="busy"
              placeholder="gitea1"
              class="mg-bottom-md"
            />
            <NsButton
              type="button"
              kind="primary"
              :icon="Add20"
              :loading="busy"
              :disabled="busy || !name.trim() || !module.trim()"
              @click="add"
              >{{ $t("c.createToken") }}</NsButton
            >
          </cv-form>
          <div v-if="token" class="token mg-top-lg">
            <NsInlineNotification
              kind="warning"
              :title="$t('c.tokenOnce')"
              :description="$t('c.sourceTokenOnce')"
              :showCloseButton="false"
            />
            <div class="bx--form__helper-text mg-bottom-sm">
              {{ $t("c.sourceToken") }}
            </div>
            <cv-code-snippet kind="multi" class="secret mg-bottom-md">{{
              token
            }}</cv-code-snippet>
            <p class="mg-bottom-sm">
              {{ $t("c.eventIngress") }}: <code>{{ endpoint }}</code>
            </p>
            <p>{{ $t("c.sourceTokenScope") }}</p>
          </div>
        </cv-tile>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column class="page-subtitle">
        <h4>{{ $t("c.registeredSources") }} ({{ sources.length }})</h4>
      </cv-column>
    </cv-row>
    <cv-row class="toolbar">
      <cv-column>
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
        <cv-tile v-if="!sources.length && !busy" light>
          <NsEmptyState :title="$t('c.noEventSources')" />
        </cv-tile>
        <cv-data-table v-else :columns="columns" :zebra="false">
          <template slot="data">
            <cv-data-table-row
              v-for="source in sources"
              :key="source.name"
              :value="source.name"
            >
              <cv-data-table-cell>{{ source.name }}</cv-data-table-cell>
              <cv-data-table-cell>{{ source.module }}</cv-data-table-cell>
              <cv-data-table-cell>{{ $t("c.authEvents") }}</cv-data-table-cell>
              <cv-data-table-cell>
                {{ sourceState(source) }}
                <p v-if="source.active === 0">
                  {{ $t("c.sourcePendingRecovery") }}
                </p>
              </cv-data-table-cell>
              <cv-data-table-cell>
                <NsButton
                  type="button"
                  kind="danger--ghost"
                  size="small"
                  :icon="TrashCan20"
                  :disabled="busy"
                  @click="toRemove = source.name"
                  >{{ $t("c.remove") }}</NsButton
                >
              </cv-data-table-cell>
            </cv-data-table-row>
          </template>
        </cv-data-table>
      </cv-column>
    </cv-row>
    <NsDangerDeleteModal
      :isShown="!!toRemove"
      :name="toRemove"
      :title="$t('c.removeTitle')"
      :warning="$t('c.removeWarning')"
      :description="$t('c.confirmRemoveSource', { name: toRemove })"
      :typeToConfirm="$t('c.typeToConfirm', { name: toRemove })"
      :cancelLabel="$t('c.cancel')"
      :deleteLabel="$t('c.removeConfirm')"
      @hide="toRemove = ''"
      @confirmDelete="remove(toRemove)"
    />
  </cv-grid>
</template>
<script>
import task from "../task";
import Add20 from "@carbon/icons-vue/es/add/20";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import TrashCan20 from "@carbon/icons-vue/es/trash-can/20";
export default {
  name: "EventSources",
  mixins: [task],
  data: () => ({
    disposed: false,
    busy: false,
    error: "",
    errors: {},
    name: "",
    module: "",
    sources: [],
    token: "",
    endpoint: "",
    toRemove: "",
    Add20,
    Renew20,
    TrashCan20,
  }),
  created() {
    this.load();
  },
  beforeDestroy() {
    this.disposed = true;
    this.clearToken();
  },
  computed: {
    columns() {
      return [
        this.$t("c.name"),
        this.$t("c.moduleIdentity"),
        this.$t("c.sourceType"),
        this.$t("c.sourceStatus"),
        "",
      ];
    },
  },
  methods: {
    sourceState(source) {
      if (source.active === 0) return this.$t("c.sourcePending");
      if (source.active === 1) return this.$t("c.sourceActive");
      return this.$t("c.unknown");
    },
    clearToken() {
      this.token = "";
      this.endpoint = "";
    },
    fieldError(field) {
      return this.errors[field] || "";
    },
    async load() {
      this.clearToken();
      this.error = "";
      this.busy = true;
      try {
        this.sources = (await this.task("list-event-sources")).sources || [];
      } catch (e) {
        this.error = e.message;
      } finally {
        this.busy = false;
      }
    },
    async add() {
      this.clearToken();
      this.error = "";
      this.errors = {};
      this.busy = true;
      try {
        const result = await this.task("add-event-source", {
          name: this.name.trim(),
          module: this.module.trim(),
        });
        if (this.disposed) return;
        this.token = result.token;
        this.endpoint = result.endpoint || "";
        this.name = "";
        this.module = "";
        this.sources = (await this.task("list-event-sources")).sources || [];
      } catch (e) {
        if (e.validation && e.validation.length) {
          e.validation.forEach((v) =>
            this.$set(
              this.errors,
              v.field || v.parameter,
              this.$t("c.err." + v.error)
            )
          );
        } else {
          this.error = e.message;
        }
      } finally {
        this.busy = false;
      }
    },
    async remove(name) {
      this.clearToken();
      this.toRemove = "";
      this.error = "";
      this.busy = true;
      try {
        await this.task("remove-event-source", { name });
        this.sources = (await this.task("list-event-sources")).sources || [];
      } catch (e) {
        this.error = e.message;
      } finally {
        this.busy = false;
      }
    },
  },
};
</script>
