<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("about.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <cv-tile light>
          <section class="logo-and-name">
            <img :src="defaultLogo" width="64" height="64" alt="Guardian" />
            <h3 class="mg-left-md">Guardian</h3>
          </section>
          <p class="mg-bottom-md">{{ $t("c.intro") }}</p>
          <p class="mg-bottom-md">{{ $t("c.aboutSources") }}</p>
          <p class="mg-bottom-md">{{ $t("c.aboutCloud") }}</p>
          <p>
            <cv-link
              href="https://github.com/Platypuschan/ns8-guardian"
              target="_blank"
              rel="noopener noreferrer"
              >{{ $t("c.documentation") }}</cv-link
            >
          </p>
        </cv-tile>
      </cv-column>
    </cv-row>
  </cv-grid>
</template>
<script>
import defaultLogo from "../assets/module_default_logo.png";

export default {
  name: "About",
  data() {
    return { defaultLogo };
  },
};
</script>
<style scoped>
.logo-and-name {
  display: flex;
  align-items: center;
  margin-bottom: 1.5rem;
}
</style>
