<!--
  Copyright (C) 2023 Nethesis S.r.l.
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <div class="app-side-menu-content">
    <div class="instance-name">
      <div v-if="instanceLabel">{{ instanceLabel }}</div>
      <div v-else-if="instanceName">{{ instanceName }}</div>
      <cv-skeleton-text
        v-else
        :width="instanceNameSkeletonWidth"
      ></cv-skeleton-text>
    </div>

    <cv-side-nav-items>
      <cv-side-nav-link
        @click="openPage('status')"
        :class="{ 'current-page': isLinkActive('status') }"
      >
        <template v-slot:nav-icon><Activity20 /></template>
        <span>{{ $t("status.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="openPage('settings')"
        :class="{ 'current-page': isLinkActive('settings') }"
      >
        <template v-slot:nav-icon><Settings20 /></template>
        <span>{{ $t("settings.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="openPage('members')"
        :class="{ 'current-page': isLinkActive('members') }"
      >
        <template v-slot:nav-icon><UserMultiple20 /></template>
        <span>{{ $t("members.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="openPage('bans')"
        :class="{ 'current-page': isLinkActive('bans') }"
      >
        <template v-slot:nav-icon><Locked20 /></template>
        <span>{{ $t("bans.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="openPage('event-sources')"
        :class="{ 'current-page': isLinkActive('event-sources') }"
      >
        <template v-slot:nav-icon><Activity20 /></template>
        <span>{{ $t("eventSources.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="openPage('about')"
        :class="{ 'current-page': isLinkActive('about') }"
      >
        <template v-slot:nav-icon><Information20 /></template>
        <span>{{ $t("about.title") }}</span>
      </cv-side-nav-link>
    </cv-side-nav-items>
  </div>
</template>

<script>
import Settings20 from "@carbon/icons-vue/es/settings/20";
import Information20 from "@carbon/icons-vue/es/information/20";
import Activity20 from "@carbon/icons-vue/es/activity/20";
import UserMultiple20 from "@carbon/icons-vue/es/user--multiple/20";
import Locked20 from "@carbon/icons-vue/es/locked/20";
import { mapState } from "vuex";
import { QueryParamService, UtilService } from "@nethserver/ns8-ui-lib";
import { navigateToPage, pageFromUrl } from "../pageSync.mjs";

export default {
  name: "AppSideMenuContent",
  components: {
    Settings20,
    Information20,
    Activity20,
    UserMultiple20,
    Locked20,
  },
  mixins: [QueryParamService, UtilService],
  data() {
    return {
      instanceNameSkeletonWidth: "70%",
    };
  },
  computed: {
    ...mapState(["instanceName", "instanceLabel", "core"]),
  },
  created() {
    // register to appNavigation event
    this.$root.$on("appNavigation", this.onAppNavigation);
  },
  beforeDestroy() {
    // remove event listener
    this.$root.$off("appNavigation");
  },
  methods: {
    isLinkActive(page) {
      // same default page as the router: settings (the library default would be status)
      return (pageFromUrl(window.parent.location.href) || "settings") === page;
    },
    // The shell only learns the page from the parent URL (goToAppPage). Switch the page here as well, so a click does not
    // wait for the URL watcher; the watcher still serves history, bookmarks and links from elsewhere.
    openPage(page) {
      this.goToAppPage(this.instanceName, page);
      navigateToPage(this.$router, this.$route, page);
      this.onAppNavigation();
    },
    onAppNavigation() {
      // highlight current page in side menu
      this.$forceUpdate();
    },
  },
};
</script>

<style scoped lang="scss">
.instance-name span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
